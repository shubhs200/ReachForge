from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


SEEDS_SPEC_SCHEMA: Dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "ReachForge2.0 SeedsSpec",
    "type": "object",
    "additionalProperties": False,
    "required": ["seeds"],
    "properties": {
        "seeds": {
            "type": "array",
            "minItems": 10,
            "maxItems": 10,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["filename", "encoding", "content"],
                "properties": {
                    "filename": {"type": "string"},
                    "encoding": {"type": "string", "enum": ["hex", "base64", "utf8"]},
                    "content": {"type": "string"},
                    "notes": {"type": "string"},
                },
            },
        },
        "harness_input_mode": {"type": "string", "enum": ["buffer", "file"]},
        "max_size_bytes": {"type": "integer", "minimum": 1},
    },
}


def write_schema_file(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(SEEDS_SPEC_SCHEMA, f, indent=2)


def _require(spec: Dict[str, Any], key: str, typ) -> Optional[str]:
    if key not in spec:
        return f"Missing required key: {key}"
    val = spec[key]
    if typ == list:
        if not isinstance(val, list):
            return f"Key '{key}' must be a list"
    elif typ == str:
        if not isinstance(val, str):
            return f"Key '{key}' must be a string"
        if val.strip() == "":
            return f"Key '{key}' must be a non-empty string"
    elif typ == int:
        if not isinstance(val, int):
            return f"Key '{key}' must be an integer"
    else:
        if not isinstance(val, typ):
            return f"Key '{key}' must be of type {typ}"
    return None


def validate_seeds_spec(spec: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    # Seeds list
    err = _require(spec, "seeds", list)
    if err:
        return False, err
    seeds = spec.get("seeds", [])
    if not isinstance(seeds, list) or len(seeds) != 10:
        return False, "seeds must be an array with exactly 10 items"
    for i, s in enumerate(seeds):
        if not isinstance(s, dict):
            return False, f"seeds[{i}] must be an object"
        for req in ("filename", "encoding", "content"):
            if req not in s or not isinstance(s[req], str) or s[req].strip() == "":
                return False, f"seeds[{i}].{req} must be a non-empty string"
        if s["encoding"] not in ("hex", "base64", "utf8"):
            return False, f"seeds[{i}].encoding must be one of hex|base64|utf8"
        if "notes" in s and not isinstance(s["notes"], str):
            return False, f"seeds[{i}].notes must be a string if provided"

    # Optional fields
    if "harness_input_mode" in spec:
        if spec["harness_input_mode"] not in ("buffer", "file"):
            return False, "harness_input_mode must be 'buffer' or 'file'"
    if "max_size_bytes" in spec:
        if not isinstance(spec["max_size_bytes"], int) or spec["max_size_bytes"] <= 0:
            return False, "max_size_bytes must be a positive integer"

    return True, None
