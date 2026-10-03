#!/usr/bin/env python3
"""Extract endpoints from Go web services and produce APIModel instances."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from tree_sitter import Node

from code_analyzer.go.bindings import find_registration_binding
from code_analyzer.go.helpers import (
    PATH_SENTINEL,
    HelperSpec,
    Registration,
    split_on_sentinel,
)
from code_analyzer.go.handler_params import (
    extract_handler_params,
    find_body_struct,
    parameter_names,
)
from code_analyzer.go.parser import GoParser, iter_nodes, node_text
from code_analyzer.go.receivers import is_router_type, receiver_could_be_router
from code_analyzer.go.path_expr import (
    collect_imports,
    collect_string_constants,
    package_name,
    resolve_path_expression,
)
from code_analyzer.go.routers import (
    GROUP_METHODS,
    LITERAL_NODE_TYPES,
    METHOD_FIRST_CANDIDATES,
    MOUNT_METHODS,
    SUPPORTED_VERBS,
    http_method,
    method_first_verb,
)
from code_analyzer.go.structs import collect_struct_types
from models.api_model import APIModel
from models.parameter import ArrayParameter, BasicParameter
from models.structure import RequestStructure, ResponseStructure
from models.types import ParamType


logger = logging.getLogger(__name__)

# Which struct tag names the field, given how the route binds it.
_TAG_PREFERENCE = {
    "body": ("json", "form", "query", "uri"),
    "query": ("form", "query", "json", "uri"),
}

# httprouter and gin name a parameter ":basket" and a catch-all "*filepath",
# while chi already writes "{basket}". The rest of the pipeline speaks the
# OpenAPI form, and so does every spec we compare against.
_COLON_PLACEHOLDER_RE = re.compile(r"[:*]([A-Za-z_][A-Za-z0-9_]*)")
_BRACE_PLACEHOLDER_RE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")
# chi and Gitea write a nameless catch-all as "/*"; it is still a parameter slot.
_BARE_WILDCARD_RE = re.compile(r"\*(?![A-Za-z_])")


@dataclass
class GoRoute:
    method: str
    path: str
    handler: str
    file_path: str
    binding: object = None


class GoApiExtractor:
    def __init__(self, project_path: str):
        self.project_path = Path(project_path)
        self.parser = GoParser()
        self._functions_by_package: dict[Path, dict[str, Node]] = {}
        self._structs_by_package: dict[Path, dict] = {}
        self._method_results_by_package: dict[Path, dict[str, set[str]]] = {}
        self._group_defs_cache: dict[int, tuple[str, list[tuple[str, str, str]]]] = {}
        self._calls_cache: dict[int, list[tuple[str, int, Node]]] = {}
        self._qualified_constants: dict[tuple[str, str], str] = {}
        self._param_prefixes: dict[tuple[str, str], str] = {}
        self._structs_by_name: dict[str, list] = {}
        self._imports_by_file: dict[str, dict[str, str]] = {}
        self._package_dirs: dict[str, Path] = {}
        self._package_of_function: dict[int, Path] = {}
        self._file_of_function: dict[int, str] = {}
        self._mount_prefixes: dict[tuple[Path, str], str] = {}
        self._helpers: dict[str, HelperSpec] = {}
        self._mount_helpers: dict[str, tuple[int, int]] = {}
        self._package_mount_prefixes: dict[Path, str] = {}

    def scan_project(self, project_path: Optional[str] = None) -> list[APIModel]:
        routes = self.collect_routes(project_path)
        return [self._build_api_model(route) for route in routes]

    def collect_routes(self, project_path: Optional[str] = None) -> list[GoRoute]:
        """Every route the project registers, in file order."""
        root = Path(project_path) if project_path else self.project_path
        trees: list[tuple[Path, object]] = []
        # A Go package is a directory, and request-baskets keeps its path
        # constants in config.go while registering routes in server.go, so
        # constants have to be indexed before any route is resolved.
        constants_by_package: dict[Path, dict[str, str]] = {}
        for go_file in sorted(root.rglob("*.go")):
            # Go excludes _test.go from the build, and a router built inside a
            # test serves no traffic -- counting it would invent endpoints.
            if go_file.name.endswith("_test.go"):
                continue
            try:
                code = go_file.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            tree = self.parser.parse(code)
            trees.append((go_file, tree))
            file_constants = collect_string_constants(tree.root_node)
            package = constants_by_package.setdefault(go_file.parent, {})
            package.update(file_constants)
            pkg_name = package_name(tree.root_node)
            if pkg_name:
                for name, value in file_constants.items():
                    self._qualified_constants[(pkg_name, name)] = value
            functions = self._functions_by_package.setdefault(go_file.parent, {})
            file_functions = _function_declarations(tree.root_node)
            functions.update(file_functions)
            for node in file_functions.values():
                self._package_of_function[node.id] = go_file.parent
                self._file_of_function[node.id] = str(go_file)
            file_structs = collect_struct_types(tree.root_node)
            structs = self._structs_by_package.setdefault(go_file.parent, {})
            structs.update(file_structs)
            for name, struct in file_structs.items():
                self._structs_by_name.setdefault(name, []).append(struct)
            self._imports_by_file[str(go_file)] = collect_imports(tree.root_node)
            relative = go_file.parent.relative_to(root).as_posix() if go_file.parent != root else ""
            if relative:
                self._package_dirs[relative] = go_file.parent
            results = self._method_results_by_package.setdefault(go_file.parent, {})
            for name, types in _result_types(tree.root_node).items():
                results.setdefault(name, set()).update(types)

        self._resolve_mount_prefixes(trees, constants_by_package)
        self._resolve_helpers(constants_by_package)
        self._resolve_param_prefixes(trees, constants_by_package)

        routes: list[GoRoute] = []
        for go_file, tree in trees:
            constants = constants_by_package.get(go_file.parent, {})
            routes.extend(self._routes_in_tree(tree, str(go_file), constants))
        return routes

    def _resolve_mount_prefixes(self, trees, constants_by_package) -> None:
        """Record the prefix each sub-router builder is mounted at.

        Gitea builds its API router in routers/api/v1 without any knowledge of
        where it will live, then ``routers/init.go`` does
        ``r.Mount("/api/v1", apiv1.Routes())``. The prefix therefore arrives
        through a cross-package return value, which neither lexical nesting nor
        variable propagation can see -- and without it every extracted API path
        is missing /api/v1 and would 404 during a scan.
        """
        self._mount_prefixes = {}
        self._package_mount_prefixes = {}
        self._mount_helpers = _mount_helper_specs(trees, self._call_arguments)
        for go_file, tree in trees:
            constants = constants_by_package.get(go_file.parent, {})
            for node in iter_nodes(tree.root_node):
                if node.type != "call_expression":
                    continue
                function = node.child_by_field_name("function")
                if function is None or function.type != "selector_expression":
                    continue
                field = function.child_by_field_name("field")
                if field is None or node_text(field) not in MOUNT_METHODS:
                    continue
                args = self._call_arguments(node)
                if len(args) < 2:
                    continue
                self._record_mount(args, 0, 1, str(go_file), constants)

            # A project may wrap Mount in its own function -- Navidrome's
            # MountRouter(description, urlPath, subRouter) -- so the prefix and
            # the sub-router arrive as arguments to that wrapper instead.
            for node in iter_nodes(tree.root_node):
                if node.type != "call_expression":
                    continue
                function = node.child_by_field_name("function")
                if function is None:
                    continue
                if function.type == "selector_expression":
                    field = function.child_by_field_name("field")
                    name = node_text(field) if field is not None else ""
                elif function.type == "identifier":
                    name = node_text(function)
                else:
                    continue
                indices = self._mount_helpers.get(name)
                if indices is None:
                    continue
                args = self._call_arguments(node)
                if max(indices) >= len(args):
                    continue
                self._record_mount(args, indices[0], indices[1], str(go_file), constants)

    def _record_mount(
        self,
        args: list[Node],
        prefix_index: int,
        router_index: int,
        file_path: str,
        constants: dict[str, str],
    ) -> None:
        prefix = self._resolve(args[prefix_index], constants)
        if not prefix or prefix == "/":
            return
        target = self._mounted_builder(args[router_index], file_path)
        if target is not None:
            self._mount_prefixes[target] = prefix
        package = self._mounted_package(args[router_index], file_path)
        if package is not None:
            self._package_mount_prefixes[package] = prefix

    def _mounted_package(self, argument: Node, file_path: str) -> Optional[Path]:
        """The package whose routes a mounted value belongs to.

        Navidrome mounts ``CreateSubsonicAPIRouter(ctx)``, whose declared result
        is ``*subsonic.Router`` -- an object, not a router built in place. The
        registrations live in that package's own methods, so the prefix is
        attributed to the package.
        """
        if argument.type != "call_expression":
            return None
        function = argument.child_by_field_name("function")
        if function is None:
            return None
        name = node_text(function).split(".")[-1]
        for package, functions in self._functions_by_package.items():
            declaration = functions.get(name)
            if declaration is None:
                continue
            result = declaration.child_by_field_name("result")
            if result is None:
                continue
            qualifier = _type_qualifier(node_text(result))
            if not qualifier:
                continue
            declaring_file = self._file_of_function.get(declaration.id)
            resolved = (
                self._package_for_qualifier(declaring_file, qualifier)
                if declaring_file
                else None
            )
            if resolved is not None:
                return resolved
        return None

    def _mounted_builder(self, argument: Node, file_path: str) -> Optional[tuple[Path, str]]:
        """(package, function) of the builder call passed to Mount."""
        if argument.type != "call_expression":
            return None
        function = argument.child_by_field_name("function")
        if function is None:
            return None
        if function.type == "identifier":
            return Path(file_path).parent, node_text(function)
        if function.type == "selector_expression":
            operand = function.child_by_field_name("operand")
            field = function.child_by_field_name("field")
            if operand is None or field is None:
                return None
            package_dir = self._package_for_qualifier(file_path, node_text(operand))
            if package_dir is None:
                return None
            return package_dir, node_text(field)
        return None

    def _mount_prefix_for(self, func_node: Node) -> str:
        package = self._package_of_function.get(func_node.id)
        name_node = func_node.child_by_field_name("name")
        if package is None:
            return ""
        if name_node is not None:
            named = self._mount_prefixes.get((package, node_text(name_node)))
            if named is not None:
                return named
        return self._package_mount_prefixes.get(package, "")

    # Cloudreve hands a group to another function -- initSlaveFileRouter(v4) --
    # so a prefix can travel through a parameter. Four rounds cover the nesting
    # depth these projects actually use.
    MAX_PREFIX_ROUNDS = 4

    def _resolve_param_prefixes(self, trees, constants_by_package) -> None:
        self._param_prefixes = {}
        parameters = {
            name: parameter_names(node)
            for functions in self._functions_by_package.values()
            for name, node in functions.items()
        }
        carriers = [
            (func, constants_by_package.get(package, {}))
            for package, functions in self._functions_by_package.items()
            for func in functions.values()
            if self._group_definitions(func, constants_by_package.get(package, {}))[1]
        ]
        for _ in range(self.MAX_PREFIX_ROUNDS):
            changed = False
            for func, constants in carriers:
                groups = self._group_variables(func, constants)
                for callee, index, argument in self._calls_cached(func):
                    names = parameters.get(callee, [])
                    if index >= len(names):
                        continue
                    prefix = self._argument_prefix(argument, groups, constants)
                    if prefix is None:
                        continue
                    key = (callee, names[index])
                    if self._param_prefixes.get(key) != prefix:
                        self._param_prefixes[key] = prefix
                        changed = True
            if not changed:
                break

    def _routes_in_tree(self, tree, file_path: str, constants: dict[str, str]) -> list[GoRoute]:
        routes: list[GoRoute] = []
        for node in iter_nodes(tree.root_node):
            if node.type != "call_expression":
                continue
            if self._inside_registration_helper(node):
                # A helper's own r.HandleFunc("/"+path, h) has no concrete path of
                # its own; those routes are counted at each of its call sites.
                continue
            route = self._route_from_call(node, file_path, constants)
            if route is not None:
                routes.append(route)
                continue
            routes.extend(self._routes_from_helper_call(node, file_path, constants))
        return routes

    def _inside_registration_helper(self, call: Node) -> bool:
        enclosing = _enclosing_function(call)
        if enclosing is None:
            return False
        name_node = enclosing.child_by_field_name("name")
        return name_node is not None and node_text(name_node) in self._helpers

    # A helper may delegate to another helper (h -> hr -> addHandler), so the
    # specs are resolved to a fixpoint. Four rounds cover the depth seen so far.
    MAX_HELPER_ROUNDS = 4

    def _resolve_helpers(self, constants_by_package) -> None:
        """Describe every function that registers a route on its own parameters."""
        self._helpers = {}
        candidates = [
            (name, func, constants_by_package.get(package, {}))
            for package, functions in self._functions_by_package.items()
            for name, func in functions.items()
        ]
        for _ in range(self.MAX_HELPER_ROUNDS):
            changed = False
            for name, func, constants in candidates:
                spec = self._helper_spec(func, constants)
                if spec is None:
                    continue
                previous = self._helpers.get(name)
                if previous is None or previous.key() != spec.key():
                    self._helpers[name] = spec
                    changed = True
            if not changed:
                break

    def _helper_spec(self, func: Node, constants: dict[str, str]) -> Optional[HelperSpec]:
        router_index, path_index, router_name, path_name = _helper_parameters(func)
        if router_index is None or path_index is None:
            return None
        scoped = dict(constants)
        scoped[path_name] = PATH_SENTINEL
        registrations: list[Registration] = []
        for node in iter_nodes(func):
            if node.type != "call_expression":
                continue
            registrations.extend(self._direct_registrations(node, router_name, scoped))
            registrations.extend(self._delegated_registrations(node, router_name, scoped))
        if not registrations:
            return None
        return HelperSpec(router_index, path_index, tuple(dict.fromkeys(registrations)))

    def _direct_registrations(
        self, call: Node, router_name: str, scoped: dict[str, str]
    ) -> list[Registration]:
        """``r.HandleFunc("/"+path, h)`` inside the helper body."""
        function = call.child_by_field_name("function")
        if function is None or function.type != "selector_expression":
            return []
        field = function.child_by_field_name("field")
        operand = _chain_base(function.child_by_field_name("operand"))
        if field is None or operand is None or operand.type != "identifier":
            return []
        if node_text(operand) != router_name:
            return []
        method = http_method(node_text(field))
        if method is None:
            return []
        args = self._call_arguments(call)
        if not args:
            return []
        resolved = self._resolve(args[0], scoped)
        parts = split_on_sentinel(resolved) if resolved is not None else None
        if parts is None:
            return []
        return [Registration(method, parts[0], parts[1])]

    def _delegated_registrations(
        self, call: Node, router_name: str, scoped: dict[str, str]
    ) -> list[Registration]:
        """``hr(r, path, f)`` -- a helper handing the work to another helper."""
        function = call.child_by_field_name("function")
        if function is None or function.type != "identifier":
            return []
        spec = self._helpers.get(node_text(function))
        if spec is None:
            return []
        args = self._call_arguments(call)
        if max(spec.router_index, spec.path_index) >= len(args):
            return []
        forwarded_router = args[spec.router_index]
        if forwarded_router.type != "identifier" or node_text(forwarded_router) != router_name:
            return []
        resolved = self._resolve(args[spec.path_index], scoped)
        parts = split_on_sentinel(resolved) if resolved is not None else None
        if parts is None:
            return []
        left, right = parts
        return [
            Registration(reg.method, reg.left + left, right + reg.right)
            for reg in spec.registrations
        ]

    def _routes_from_helper_call(
        self, call: Node, file_path: str, constants: dict[str, str]
    ) -> list[GoRoute]:
        """Routes produced by calling a project-local registration helper."""
        function = call.child_by_field_name("function")
        if function is None:
            return []
        if function.type == "identifier":
            name = node_text(function)
        elif function.type == "selector_expression":
            field = function.child_by_field_name("field")
            name = node_text(field) if field is not None else ""
        else:
            return []
        spec = self._helpers.get(name)
        if spec is None:
            return []
        args = self._call_arguments(call)
        if max(spec.router_index, spec.path_index) >= len(args):
            return []
        router_arg = args[spec.router_index]
        if router_arg.type != "identifier":
            return []
        value = self._resolve(args[spec.path_index], constants)
        if value is None:
            return []
        prefix = join_path(
            self._identifier_prefix(call, node_text(router_arg), constants),
            self._lexical_prefix(call, constants),
        )
        handler = node_text(args[-1])
        return [
            GoRoute(
                method=reg.method,
                path=join_path(prefix, reg.path_for(value)),
                handler=handler,
                file_path=file_path,
                binding=find_registration_binding(args, skip_first=False),
            )
            for reg in spec.registrations
        ]

    def _route_from_call(
        self, call: Node, file_path: str, constants: dict[str, str]
    ) -> Optional[GoRoute]:
        function = call.child_by_field_name("function")
        if function is None or function.type != "selector_expression":
            return None
        field = function.child_by_field_name("field")
        if field is None:
            return None
        call_name = node_text(field)
        method = http_method(call_name)
        if method is None:
            return None
        args = self._call_arguments(call)
        if not args:
            return None
        path_index = 0
        if call_name in METHOD_FIRST_CANDIDATES and len(args) >= 3:
            named = method_first_verb(self._resolve(args[0], constants))
            if named is not None:
                if named not in SUPPORTED_VERBS:
                    return None
                method, path_index = named, 1
        handler = args[-1]
        if handler.type in LITERAL_NODE_TYPES:
            return None
        operand = function.child_by_field_name("operand")
        if not self._receiver_is_router(call, operand):
            return None
        # Gitea chains verbs off one path: m.Combo("/x").Get(h).Patch(h).
        combo_path = self._combo_path(operand, constants) if operand is not None else None
        path = combo_path
        if path is None:
            if len(args) < 2:
                return None
            path = self._resolve(args[path_index], constants)
        if path is None:
            return None
        prefix = join_path(
            self._receiver_prefix(call, function, constants),
            self._lexical_prefix(call, constants),
        )
        path = join_path(prefix, path)
        return GoRoute(
            method=method,
            path=path,
            handler=node_text(handler),
            file_path=file_path,
            binding=find_registration_binding(args, skip_first=combo_path is None),
        )

    def _receiver_is_router(self, call: Node, operand: Optional[Node]) -> bool:
        """Whether the receiver could be a router.

        A chain whose base is not a plain identifier -- ``ds.Property(ctx).Put``
        -- is a method on some other object, and a base declared with a
        non-router type is too. Everything else is accepted, because the router
        may be a package-level variable this function never declares.
        """
        base = _chain_base(operand)
        if base is None or base.type != "identifier":
            return False
        return receiver_could_be_router(call, node_text(base))

    def _combo_path(self, operand: Node, constants: dict[str, str]) -> Optional[str]:
        """The path of the ``Combo`` call this verb is chained off, if any."""
        node = operand
        while node is not None and node.type == "call_expression":
            function = node.child_by_field_name("function")
            if function is None or function.type != "selector_expression":
                return None
            field = function.child_by_field_name("field")
            name = node_text(field) if field is not None else ""
            if name == "Combo":
                args = self._call_arguments(node)
                return self._resolve(args[0], constants) if args else None
            if http_method(name) is None:
                return None
            node = function.child_by_field_name("operand")
        return None

    def _receiver_prefix(
        self, call: Node, function: Node, constants: dict[str, str]
    ) -> str:
        """The prefix carried by the variable this route was registered on.

        gin hands a group back as a value -- ``v4 := r.Group("/api/slave")``,
        then ``file := v4.Group("file")`` -- so the prefix travels through
        variables rather than through nesting. The map is built per enclosing
        function so that two functions reusing the name ``api`` stay apart.
        """
        operand = _chain_base(function.child_by_field_name("operand"))
        if operand is None or operand.type != "identifier":
            return ""
        enclosing = _enclosing_function(call)
        if enclosing is None:
            return ""
        return self._identifier_prefix(call, node_text(operand), constants)

    def _identifier_prefix(self, call: Node, name: str, constants: dict[str, str]) -> str:
        enclosing = _enclosing_function(call)
        if enclosing is None:
            return ""
        groups = self._group_variables(enclosing, constants)
        if name in groups:
            return groups[name]
        enclosing_name = enclosing.child_by_field_name("name")
        if enclosing_name is not None:
            inherited = self._param_prefixes.get((node_text(enclosing_name), name))
            if inherited is not None:
                return inherited
        return self._mount_prefix_for(enclosing)

    def _group_variables(self, func_node: Node, constants: dict[str, str]) -> dict[str, str]:
        """Resolve this function's group variables to concrete prefixes."""
        func_name, definitions = self._group_definitions(func_node, constants)
        groups: dict[str, str] = {}
        root_prefix = self._mount_prefix_for(func_node)
        for name, parent, segment in definitions:
            parent_prefix = groups.get(parent)
            if parent_prefix is None:
                parent_prefix = self._param_prefixes.get((func_name, parent))
            if parent_prefix is None:
                parent_prefix = root_prefix
            groups[name] = join_path(parent_prefix, segment)
        return groups

    def _group_definitions(
        self, func_node: Node, constants: dict[str, str]
    ) -> tuple[str, list[tuple[str, str, str]]]:
        """(function name, [(variable, parent variable, path segment)]), cached.

        Walking the AST is the expensive part and its result never changes, so
        the prefix fixpoint re-resolves these tuples instead of re-parsing.
        """
        cached = self._group_defs_cache.get(func_node.id)
        if cached is not None:
            return cached
        name_node = func_node.child_by_field_name("name")
        func_name = node_text(name_node) if name_node is not None else ""
        definitions: list[tuple[str, str, str]] = []
        # A nested group reads the prefix its parent variable already carries,
        # so these have to be resolved in source order -- iter_nodes walks a
        # stack and would otherwise reach "file := v4.Group(...)" first.
        declarations = sorted(
            (node for node in iter_nodes(func_node) if node.type == "short_var_declaration"),
            key=lambda node: node.start_byte,
        )
        for node in declarations:
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is None or right is None:
                continue
            names = list(left.named_children)
            values = list(right.named_children) if right.type == "expression_list" else [right]
            for name_node, value_node in zip(names, values):
                segment = self._value_group_segment(value_node, constants)
                if segment is None:
                    continue
                definitions.append(
                    (node_text(name_node), self._value_group_receiver(value_node), segment)
                )
        result = (func_name, definitions)
        self._group_defs_cache[func_node.id] = result
        return result

    def _calls_cached(self, func_node: Node) -> list[tuple[str, int, str]]:
        cached = self._calls_cache.get(func_node.id)
        if cached is None:
            cached = list(_identifier_calls(func_node))
            self._calls_cache[func_node.id] = cached
        return cached

    def _argument_prefix(
        self, argument: Node, groups: dict[str, str], constants: dict[str, str]
    ) -> Optional[str]:
        """The routed prefix an argument carries, if any.

        Alist creates the group right in the call -- ``_fs(auth.Group("/fs"))``
        -- rather than binding it to a variable first, so an argument may be a
        group-producing expression and not just a name.
        """
        if argument.type == "identifier":
            return groups.get(node_text(argument))
        segment = self._value_group_segment(argument, constants)
        if segment is None:
            return None
        parent_prefix = groups.get(self._value_group_receiver(argument))
        if parent_prefix is None:
            return None
        return join_path(parent_prefix, segment)

    def _value_group_segment(self, value: Node, constants: dict[str, str]) -> Optional[str]:
        """The path a ``x := recv.Group("p")`` call contributes, if it is one."""
        if value.type != "call_expression":
            return None
        function = value.child_by_field_name("function")
        if function is None or function.type != "selector_expression":
            return None
        field = function.child_by_field_name("field")
        if field is None or node_text(field) not in GROUP_METHODS:
            return None
        args = self._call_arguments(value)
        # A closure argument means the scope is lexical, not value-carried.
        if not args or any(arg.type == "func_literal" for arg in args[1:]):
            return None
        return self._resolve(args[0], constants)

    @staticmethod
    def _value_group_receiver(value: Node) -> str:
        function = value.child_by_field_name("function")
        operand = function.child_by_field_name("operand") if function is not None else None
        return node_text(operand) if operand is not None else ""

    def _lexical_prefix(self, call: Node, constants: dict[str, str]) -> str:
        """Prefixes contributed by the routed scopes this call is nested in.

        chi writes ``r.Route("/x", func(r chi.Router){...})`` and Gitea writes
        ``m.Group("/x", func(){...})``; both bind the scope lexically, so
        walking up the tree covers them with one mechanism. chi's ``Group(fn)``
        takes no path and contributes nothing -- treating it as a prefix would
        corrupt every route beneath it.
        """
        segments: list[str] = []
        node = call.parent
        while node is not None:
            if node.type == "call_expression":
                segment = self._group_segment(node, constants)
                if segment:
                    segments.append(segment)
            node = node.parent
        prefix = ""
        for segment in reversed(segments):
            prefix = join_path(prefix, segment)
        return prefix

    def _group_segment(self, call: Node, constants: dict[str, str]) -> Optional[str]:
        function = call.child_by_field_name("function")
        if function is None or function.type != "selector_expression":
            return None
        field = function.child_by_field_name("field")
        if field is None or node_text(field) not in GROUP_METHODS:
            return None
        args = self._call_arguments(call)
        # Only a (path, closure, ...middleware) shape opens a prefixed scope.
        # Gitea writes m.Group("/branches", func(){...}, reqRepoReader(unit)),
        # so the closure is not always the final argument.
        if len(args) < 2 or not any(arg.type == "func_literal" for arg in args[1:]):
            return None
        return self._resolve(args[0], constants)

    def _resolve(self, node: Node, constants: dict[str, str]) -> Optional[str]:
        return resolve_path_expression(node, constants, self._qualified_constants)

    @staticmethod
    def _call_arguments(call: Node) -> list[Node]:
        arg_list = call.child_by_field_name("arguments")
        if arg_list is None:
            return []
        return [child for child in arg_list.named_children if child.type != "comment"]

    def _build_api_model(self, route: GoRoute) -> APIModel:
        url, path_params = normalize_route_path(route.path)
        request = RequestStructure()
        for name in path_params:
            request.path[name] = BasicParameter(name, ParamType.STRING, is_required=True)
        handler = self._handler_node(route)
        if handler is not None:
            handler_package = self._package_of_node(handler) or Path(route.file_path).parent
            package_functions = self._functions_by_package.get(handler_package, {})
            params = extract_handler_params(handler, package_functions)
            for name, param_type in params.query.items():
                request.query[name] = BasicParameter(name, param_type)
            for name, param_type in params.header.items():
                request.header[name] = BasicParameter(name, param_type)
            for name, param_type in params.path.items():
                request.path.setdefault(name, BasicParameter(name, param_type, is_required=True))
            self._apply_body_struct(route, handler, request)
        self._apply_registration_binding(route, request)
        return APIModel(
            api_url=url,
            api_method=route.method,
            request_structure=request,
            response_structure=ResponseStructure(),
        )


    def _package_of_node(self, node: Node) -> Optional[Path]:
        return self._package_of_function.get(node.id)

    def _apply_registration_binding(
        self, route: GoRoute, request: RequestStructure
    ) -> None:
        binding = route.binding
        if binding is None:
            return
        struct = self._lookup_struct(route, binding)
        if struct is None:
            return
        for field in struct.fields:
            # The tag that matches the binding names the field on the wire:
            # FromQuery reads `form:"path"`, FromJSON reads `json:"callback"`.
            # A `uri` tag marks a path parameter whatever the binding is.
            tag = next(
                (name for name in _TAG_PREFERENCE[binding.location] if name in field.tags),
                None,
            )
            name = field.tags[tag] if tag else field.name
            location = "path" if tag == "uri" else binding.location
            section = getattr(request, location)
            section[name] = _parameter_for(field, name)

    def _lookup_struct(self, route: GoRoute, binding):
        """Find the struct a binding names, following the file's imports.

        Gitea and Cloudreve both import the package under an alias -- ``api``
        for modules/structs, ``adminsvc`` for service/admin -- so the qualifier
        is not the package name and duplicate type names are common. Resolving
        the alias to its import path pins the right one; the project-wide
        fallback applies only when the name is unambiguous.
        """
        type_name = binding.type_name
        qualifier = getattr(binding, "qualifier", "")
        if qualifier:
            package_dir = self._package_for_qualifier(route.file_path, qualifier)
            if package_dir is not None:
                found = self._structs_by_package.get(package_dir, {}).get(type_name)
                if found is not None:
                    return found
        else:
            local = self._structs_by_package.get(Path(route.file_path).parent, {}).get(type_name)
            if local is not None:
                return local
        candidates = self._structs_by_name.get(type_name, [])
        return candidates[0] if len(candidates) == 1 else None

    def _package_for_qualifier(self, file_path: str, qualifier: str) -> Optional[Path]:
        import_path = self._imports_by_file.get(file_path, {}).get(qualifier)
        if not import_path:
            return None
        for relative, directory in self._package_dirs.items():
            if import_path == relative or import_path.endswith("/" + relative):
                return directory
        return None

    def _apply_body_struct(
        self, route: GoRoute, handler: Node, request: RequestStructure
    ) -> None:
        """Body fields from the struct the handler decodes into.

        The struct lives beside the handler, not beside the route: Alist
        registers ``handles.FsMkdir`` from package ``server`` while
        ``MkdirOrLinkReq`` is declared in ``server/handles``. Looking in the
        route's package found nothing for either Alist or Gitea.
        """
        package = self._package_of_node(handler) or Path(route.file_path).parent
        struct_name = find_body_struct(
            handler, self._method_results_by_package.get(package, {})
        )
        if not struct_name:
            return
        struct = self._structs_by_package.get(package, {}).get(struct_name)
        if struct is None:
            candidates = self._structs_by_name.get(struct_name, [])
            struct = candidates[0] if len(candidates) == 1 else None
        if struct is None:
            return
        for field in struct.fields:
            request.body[field.name] = _parameter_for(field)

    def _handler_node(self, route: GoRoute) -> Optional[Node]:
        """The handler's declaration, which is usually in another package.

        Gitea registers ``m.Get("/issues", repo.ListIssues)`` in api.go while
        ListIssues lives in routers/api/v1/repo, so a local lookup finds almost
        nothing; the qualifier has to be resolved through the file's imports.
        """
        handler = route.handler.strip().lstrip("&")
        name = handler.split(".")[-1]
        qualifier = handler.rsplit(".", 1)[0].split(".")[-1] if "." in handler else ""
        if qualifier:
            package_dir = self._package_for_qualifier(route.file_path, qualifier)
            if package_dir is not None:
                found = self._functions_by_package.get(package_dir, {}).get(name)
                if found is not None:
                    return found
        local = self._functions_by_package.get(Path(route.file_path).parent, {}).get(name)
        if local is not None:
            return local
        candidates = [
            node
            for functions in self._functions_by_package.values()
            if (node := functions.get(name)) is not None
        ]
        return candidates[0] if len(candidates) == 1 else None


def _type_qualifier(type_text: str) -> str:
    """'subsonic' for ``*subsonic.Router``; empty when the type is unqualified."""
    cleaned = type_text.strip().lstrip("*")
    if "." not in cleaned:
        return ""
    return cleaned.rsplit(".", 1)[0].split(".")[-1]


def _mount_helper_specs(trees, call_arguments) -> dict[str, tuple[int, int]]:
    """Functions that wrap Mount, mapped to (prefix index, sub-router index)."""
    specs: dict[str, tuple[int, int]] = {}
    for _, tree in trees:
        for func in _function_declarations(tree.root_node).values():
            name_node = func.child_by_field_name("name")
            if name_node is None:
                continue
            params = parameter_names(func)
            if not params:
                continue
            for node in iter_nodes(func):
                if node.type != "call_expression":
                    continue
                function = node.child_by_field_name("function")
                if function is None or function.type != "selector_expression":
                    continue
                field = function.child_by_field_name("field")
                if field is None or node_text(field) not in MOUNT_METHODS:
                    continue
                args = call_arguments(node)
                if len(args) < 2:
                    continue
                if args[0].type != "identifier" or args[1].type != "identifier":
                    continue
                prefix_name, router_name = node_text(args[0]), node_text(args[1])
                if prefix_name in params and router_name in params:
                    specs[node_text(name_node)] = (
                        params.index(prefix_name),
                        params.index(router_name),
                    )
    return specs


def _helper_parameters(func: Node) -> tuple[Optional[int], Optional[int], str, str]:
    """(router index, path index, router name, path name) of a helper candidate."""
    parameters = func.child_by_field_name("parameters")
    if parameters is None:
        return None, None, "", ""
    router_index = path_index = None
    router_name = path_name = ""
    index = 0
    for declaration in parameters.named_children:
        if declaration.type != "parameter_declaration":
            continue
        type_node = declaration.child_by_field_name("type")
        type_text = node_text(type_node) if type_node is not None else ""
        names = declaration.children_by_field_name("name") or [None]
        for name_node in names:
            name = node_text(name_node) if name_node is not None else ""
            if router_index is None and is_router_type(type_text):
                router_index, router_name = index, name
            elif path_index is None and type_text.strip() == "string":
                path_index, path_name = index, name
            index += 1
    return router_index, path_index, router_name, path_name


def _chain_base(operand: Optional[Node]) -> Optional[Node]:
    """Follow a chained receiver down to the identifier it started from.

    ``m.Combo("/{org}").Get(h).Delete(h)`` registers Delete on a call, not on
    ``m``; the prefix still belongs to ``m``, so the chain has to be walked back.
    """
    node = operand
    while node is not None and node.type == "call_expression":
        function = node.child_by_field_name("function")
        if function is None or function.type != "selector_expression":
            return node
        node = function.child_by_field_name("operand")
    return node


def _identifier_calls(func_node: Node):
    """Yield (callee, arg_index, argument node) for plain ``f(a, b)`` calls."""
    for node in iter_nodes(func_node):
        if node.type != "call_expression":
            continue
        function = node.child_by_field_name("function")
        if function is None or function.type != "identifier":
            continue
        arguments = node.child_by_field_name("arguments")
        if arguments is None:
            continue
        args = [child for child in arguments.named_children if child.type != "comment"]
        for index, argument in enumerate(args):
            yield node_text(function), index, argument


def _enclosing_function(node: Node) -> Optional[Node]:
    current = node.parent
    while current is not None:
        if current.type in ("function_declaration", "method_declaration"):
            return current
        current = current.parent
    return None


def _result_types(root: Node) -> dict[str, set[str]]:
    """Map a function or method name to the single result type it declares."""
    results: dict[str, set[str]] = {}
    for node in iter_nodes(root):
        if node.type not in ("function_declaration", "method_declaration"):
            continue
        name = node.child_by_field_name("name")
        result = node.child_by_field_name("result")
        if name is None or result is None or result.type != "type_identifier":
            continue
        results.setdefault(node_text(name), set()).add(node_text(result))
    return results


def _function_declarations(root: Node) -> dict[str, Node]:
    functions: dict[str, Node] = {}
    for node in iter_nodes(root):
        if node.type not in ("function_declaration", "method_declaration"):
            continue
        name = node.child_by_field_name("name")
        if name is not None:
            functions[node_text(name)] = node
    return functions


def _parameter_for(field, name: Optional[str] = None):
    """Build the Parameter a struct field describes, array-aware."""
    field_name = name or field.name
    if getattr(field, "is_array", False):
        item = BasicParameter(field_name + "Item", field.param_type)
        return ArrayParameter(field_name, item=item)
    return BasicParameter(field_name, field.param_type)


def join_path(prefix: str, segment: str) -> str:
    """Join a routed-scope prefix with a route segment.

    gin writes its segments without a leading slash (``v4.Group("file")`` then
    ``file.GET("list", h)``), and chi writes ``r.Get("/", h)`` to mean the
    scope's own path, so neither a missing nor a doubled slash can be assumed.
    """
    head = prefix.rstrip("/")
    tail = segment.strip()
    if not tail or tail == "/":
        return head or "/"
    # Gitea concatenates raw (modules/web getPattern), which is how
    # m.Get(".diff", h) under /{index} serves /{index}.diff. A segment opening
    # with "." is a suffix on the previous one, never a new path segment.
    if tail.startswith("."):
        return (head + tail) if head else tail
    if not tail.startswith("/"):
        tail = "/" + tail
    return head + tail


def normalize_route_path(path: str) -> tuple[str, list[str]]:
    """Rewrite router placeholders to the OpenAPI form and name the parameters."""
    url = _COLON_PLACEHOLDER_RE.sub(lambda m: "{" + m.group(1) + "}", path)
    url = _BARE_WILDCARD_RE.sub("{wildcard}", url)
    return url, _BRACE_PLACEHOLDER_RE.findall(url)
