import json
import yaml
import jsonref
from collections.abc import Mapping, Sequence
from typing import Dict, Any

class APIDocLoader:
    def __init__(self, spec_path: str):
        self.spec = self._load_and_dereference(spec_path)
        self.index: Dict[str, Any] = {} 
        self._build_index()

    def _load_and_dereference(self, path: str) -> dict:
        with open(path, 'r', encoding='utf-8') as f:
            if path.endswith('.yaml') or path.endswith('.yml'):
                base = yaml.safe_load(f)
            else:
                base = json.load(f)
        
        return jsonref.replace_refs(base, base_uri=path, proxies=False)

    def _build_index(self):

        paths = self.spec.get('paths', {})
        if not paths:
            raise ValueError("No paths found in the spec")
        for path_url, methods in paths.items():
            for method, details in methods.items():
                if method.lower() not in ['get', 'post', 'put', 'patch', 'delete']:
                    continue                
                key = f"{method.upper()} {path_url}"
                self.index[key] = details

    def get_doc(self, method: str, url: str) -> str:
        key = f"{method.upper()} {url}"
        data = self.index.get(key)
        
        if not data:
            return "{}"
            
        safe_data = self._sanitize_for_json(data, set())
        return json.dumps(safe_data, indent=2)

    def _sanitize_for_json(self, obj: Any, stack: set[int]) -> Any:
        if obj is None or isinstance(obj, (str, int, float, bool)):
            return obj
        if isinstance(obj, (bytes, bytearray, memoryview)):
            return f"<bytes length={len(obj)}>"
        obj_id = id(obj)
        if obj_id in stack:
            return "<circular>"
        if isinstance(obj, Mapping):
            stack.add(obj_id)
            out = {str(k): self._sanitize_for_json(v, stack) for k, v in obj.items()}
            stack.remove(obj_id)
            return out
        if isinstance(obj, Sequence):
            stack.add(obj_id)
            out = [self._sanitize_for_json(v, stack) for v in obj]
            stack.remove(obj_id)
            return out
        return str(obj)
