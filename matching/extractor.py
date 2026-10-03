# matching/extractor.py
from ctypes import Array
from dataclasses import dataclass
from typing import Dict, Any
from models.parameter import Parameter, BasicParameter, ArrayParameter, PropertyParameter
from models.ref import FieldRef, ParamLocation, FieldPath
from models.api_model import APIModel

@dataclass(frozen=True)
class FieldExtractor:

    def resolve_request_param(self, field: FieldRef) -> Parameter:
        api_model = field.api
        if field.location == ParamLocation.PATH:
            extract = api_model.request_structure.path
        elif field.location == ParamLocation.HEADER:
            extract = api_model.request_structure.header
        elif field.location == ParamLocation.QUERY:
            extract = api_model.request_structure.query
        elif field.location == ParamLocation.BODY:
            extract = api_model.request_structure.body
        else:
            raise ValueError(f"Invalid location: {field.location}")
        return self.get_papram(field, extract)
            
    def get_papram(self, field: FieldRef, dic:dict[str, Any]) -> Parameter:
        for name in field.path.segments:
            while True:
                if isinstance(dic, ArrayParameter):
                    dic = dic.item # type: ignore
                else:
                    break
            if isinstance(dic, PropertyParameter):
                dic = dic.properties[name] # type: ignore
            elif isinstance(dic, Dict):
                dic = dic[name] # type: ignore
            else:
                raise ValueError(f"Invalid type: {type(dic)}")
        assert isinstance(dic, BasicParameter), f"Invalid type: {type(dic)}, name: {name}"
        return dic

    def request_fields(
        self, api: APIModel, include_basic_array_items: bool = False
    ) -> list[FieldRef]:
        """Request fields of ``api``.

        ``include_basic_array_items`` also yields the element of a ``[]string``
        style array -- Alist's offline download takes its URL list that way, and
        Cloudreve's remote download likewise. It is off by default because
        dependency matching and sequence planning rely on the older behaviour of
        only descending into arrays of objects.
        """
        out: list[FieldRef] = []
        for loc, mp in (
            (ParamLocation.PATH, api.request_structure.path),
            (ParamLocation.HEADER, api.request_structure.header),
            (ParamLocation.QUERY, api.request_structure.query),
            (ParamLocation.BODY, api.request_structure.body),
        ):
            self._collect_map(api, loc, mp, out,
                              include_basic_array_items=include_basic_array_items)
        return out

    def response_fields(self, api: APIModel) -> list[FieldRef]:
        out: list[FieldRef] = []
        self._collect_map(api, ParamLocation.HEADER, api.response_structure.header, out)
        self._collect_map(api, ParamLocation.BODY,   api.response_structure.body,   out)
        return out

    # ---- helpers ----
    def _collect_map(self, api: APIModel, loc: ParamLocation, mp, sink: list[FieldRef],
                     prefix: tuple[str, ...]=(), include_basic_array_items: bool = False):
        for name, p in mp.items():
            self._collect_param(api, loc, name, p, sink, prefix,
                                include_basic_array_items=include_basic_array_items)

    def _collect_param(self, api: APIModel, loc: ParamLocation, name: str, p: Parameter,
                       sink: list[FieldRef], prefix: tuple[str, ...]=(),
                       include_basic_array_items: bool = False):
        if isinstance(p, BasicParameter):
            sink.append(FieldRef(api, loc, name, p.param_type, FieldPath(prefix+(name,)), p))
        elif isinstance(p, ArrayParameter):
            if isinstance(p.item, PropertyParameter):
                self._collect_param(api, loc, name, p.item, sink, prefix,
                                    include_basic_array_items=include_basic_array_items)
            elif include_basic_array_items and isinstance(p.item, BasicParameter):
                # The payload is written onto the item, so the materializer
                # renders the array as ["payload"].
                sink.append(
                    FieldRef(api, loc, name, p.item.param_type,
                             FieldPath(prefix+(name,)), p.item)
                )
        elif isinstance(p, PropertyParameter):
            for k, v in p.properties.items():
                self._collect_param(api, loc, k, v, sink, prefix+(name,),
                                    include_basic_array_items=include_basic_array_items)
