from __future__ import annotations
import re
from dataclasses import dataclass
from pathlib import Path
import xml.etree.ElementTree as ET
from typing import Optional
import logging


logger = logging.getLogger(__name__)


@dataclass
class MyBatisMapper:
    namespace: str
    file_path: str
    # str is method, aka id,
    operations: dict[str, MyBatisOperation]


@dataclass
class MyBatisOperation:
    method_name: str
    parameters: list[MyBatisParameter]
    xml_text: str = ""


@dataclass
class MyBatisParameter:
    param_name: str


SQL_OPERATION = ["select", "insert", "update", "delete"]


class MyBatisAnalyzer:

    def __init__(self):
        self.mappers: dict[str, MyBatisMapper] = {}

    def analyze_project_mybatis(self, project_path: str):
        project_root = Path(project_path)
        # common mapper locations
        xml_files = list(project_root.glob("**/mybatis/**/*.xml"))
        xml_files += list(project_root.glob("**/mapper/**/*.xml"))
        xml_files += list(project_root.glob("**/mappers/**/*.xml"))
        for xml_file in xml_files:
            self.analyze_mapper_file(str(xml_file))

    def analyze_project_roots(self, project_paths: list[Path]):
        seen: set[Path] = set()
        for project_path in project_paths:
            project_root = Path(project_path)
            xml_files = list(project_root.glob("**/mybatis/**/*.xml"))
            xml_files += list(project_root.glob("**/mapper/**/*.xml"))
            xml_files += list(project_root.glob("**/mappers/**/*.xml"))
            for xml_file in xml_files:
                if xml_file in seen:
                    continue
                seen.add(xml_file)
                self.analyze_mapper_file(str(xml_file))

    def analyze_mapper_file(self, file_path: str):
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            namespace = root.get("namespace", "")
            if not namespace:
                return

            self.mappers[namespace] = MyBatisMapper(
                namespace=namespace, file_path=file_path, operations={}
            )

            for elem in root.iter():
                if elem.tag in SQL_OPERATION:
                    operation = self.analyze_sql_operation(elem)
                    if operation:
                        self.mappers[namespace].operations[operation.method_name] = operation

        except (OSError, ET.ParseError) as e:
            logger.warning("Error analyzing mapper file %s: %s", file_path, e)
            return

    def analyze_sql_operation(self, elem: ET.Element) -> Optional[MyBatisOperation]:
        method_name = elem.get("id", "")
        if not method_name:
            return None

        sql_text = (elem.text.strip() if elem.text else "") + "".join(elem.itertext())
        mybatis_params = self._extract_parameter_names(sql_text)
        for child in elem.iter():
            for attr_name, attr_value in child.attrib.items():
                if attr_name in {"test", "collection"}:
                    mybatis_params.extend(self._extract_expression_names(attr_value))

        mybatis_params = list(set(mybatis_params))
        operation = MyBatisOperation(
            method_name=method_name,
            parameters=[MyBatisParameter(param_name=param_name) for param_name in mybatis_params],
            xml_text=ET.tostring(elem, encoding="unicode"),
        )
        return operation

    def _extract_parameter_names(self, sql_text: str) -> list[str]:
        names: list[str] = []
        for match in re.finditer(r"[#$]\{\s*([^,}:\s]+)", sql_text or ""):
            names.extend(self._names_from_reference(match.group(1)))
        return names

    def _extract_expression_names(self, expression: str) -> list[str]:
        names: list[str] = []
        pattern = r"([A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)*)\s*(\()?"
        for match in re.finditer(pattern, expression or ""):
            token, call = match.group(1), match.group(2)
            if token in {"and", "or", "null", "true", "false"}:
                continue
            if call and "." in token:
                # `sort.trim()` names the parameter `sort`; the trailing segment is the
                # method being called on it, not a property that could be bound.
                token = token.rsplit(".", 1)[0]
            names.extend(self._names_from_reference(token))
        return names

    def _names_from_reference(self, ref: str) -> list[str]:
        text = (ref or "").strip()
        if not text:
            return []
        parts = [part for part in text.split(".") if part]
        if not parts:
            return []
        if parts[0] in {"_parameter", "param", "params", "map"} and len(parts) > 1:
            return [parts[-1]]
        if len(parts) > 1:
            return [parts[0], parts[-1]]
        return [parts[0]]
