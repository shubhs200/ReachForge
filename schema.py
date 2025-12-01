from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# JSON schema (informational)
DRIVER_SPEC_SCHEMA: Dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "ReachForge2.0 DriverSpec",
    "type": "object",
    "additionalProperties": False,
    "required": ["driver_filename", "language", "includes", "driver_source", "required_link_libs"],
    "properties": {
        "driver_filename": {"type": "string"},
        "language": {"type": "string", "enum": ["c", "c++"]},
        "includes": {"type": "array", "items": {"type": "string"}},
        "driver_source": {"type": "string"},
        "required_link_libs": {"type": "array", "items": {"type": "string"}},
        "compile_defines": {"type": "array", "items": {"type": "string"}},
        "required_compile_flags": {"type": "array", "items": {"type": "string"}},
        "extra_sources": {"type": "array", "items": {"type": "string"}},
        "lift_from_entry": {"type": "array", "items": {"type": "string"}},
        "notes": {"type": "string"},
    },
}


def write_schema_file(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(DRIVER_SPEC_SCHEMA, f, indent=2)


def _require(spec: Dict[str, Any], key: str, typ, allow_empty: bool = False) -> Optional[str]:
    if key not in spec:
        return f"Missing required key: {key}"
    val = spec[key]
    if typ == list:
        if not isinstance(val, list):
            return f"Key '{key}' must be a list"
        if not allow_empty and len(val) == 0:
            return f"Key '{key}' must be a non-empty list"
    elif typ == str:
        if not isinstance(val, str):
            return f"Key '{key}' must be a string"
        if not allow_empty and val.strip() == "":
            return f"Key '{key}' must be a non-empty string"
    else:
        if not isinstance(val, typ):
            return f"Key '{key}' must be of type {typ}"
    return None


def _enum(spec: Dict[str, Any], key: str, allowed: List[str]) -> Optional[str]:
    v = spec.get(key)
    if v not in allowed:
        return f"Key '{key}' must be one of {allowed}, got {v!r}"
    return None


def _opt_is_str(spec: Dict[str, Any], key: str) -> Optional[str]:
    if key in spec and not isinstance(spec[key], str):
        return f"Optional key '{key}' must be a string if provided"
    return None


def _opt_is_list_of_str(spec: Dict[str, Any], key: str) -> Optional[str]:
    if key in spec:
        val = spec[key]
        if not isinstance(val, list) or any(not isinstance(x, str) for x in val):
            return f"Optional key '{key}' must be a list of strings if provided"
    return None


def validate_driver_spec(spec: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    # Required
    err = _require(spec, "driver_filename", str)
    if err:
        return False, err
    err = _require(spec, "language", str)
    if err:
        return False, err
    err = _enum(spec, "language", ["c", "c++"])
    if err:
        return False, err
    err = _require(spec, "includes", list, allow_empty=True)
    if err:
        return False, err
    err = _require(spec, "driver_source", str)
    if err:
        return False, err
    err = _require(spec, "required_link_libs", list, allow_empty=True)
    if err:
        return False, err

    # Optional fields
    for k in ["notes"]:
        err = _opt_is_str(spec, k)
        if err:
            return False, err
    for k in ["compile_defines", "required_compile_flags", "includes", "required_link_libs", "extra_sources", "lift_from_entry"]:
        err = _opt_is_list_of_str(spec, k)
        if err:
            return False, err

    return True, None
