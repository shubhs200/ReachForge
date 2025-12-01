from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional, Tuple

import requests


def _read_text(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8")
    except Exception:
        return ""


def run_openai_json(prompt_path: Path, out_path: Path, *, model: str, api_base: Optional[str] = None) -> Tuple[bool, str]:
    """
    Minimal JSON-only chat wrapper.
    - Reads prompt markdown from prompt_path
    - Calls {api_base or https://api.openai.com/v1}/chat/completions
    - Writes the assistant message content to out_path (as-is)
    - Returns (ok, msg)

    Requirements:
      - Env OPENAI_API_KEY must be set (Bearer token)
      - `requests` must be installed (see reachforge4/requirements.txt)

    Notes:
      - This helper does not add additional retrieval logic; RF4 handles that.
      - We ask the model to output ONLY a single JSON object. RF4 callers may
        further validate/clip code fences where necessary.
    """
    prompt_path = Path(prompt_path).resolve()
    out_path = Path(out_path).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    api_key = os.getenv("OPENAI_API_KEY") or os.getenv("OPENAI_API_TOKEN")
    if not api_key:
        return False, "missing OPENAI_API_KEY"

    base = (api_base or "https://api.openai.com/v1").rstrip("/")
    url = f"{base}/chat/completions"

    prompt = _read_text(prompt_path)
    if not prompt.strip():
        return False, "empty prompt"

    # System instruction: JSON-only; no code fences, no prose
    system_msg = (
        "You are a code generator that must output ONLY a single JSON object with no code fences and no prose. "
        "Do not add explanations or extra text before or after the JSON."
    )

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    # Some providers support response_format={"type":"json_object"} (OpenAI JSON mode).
    # We include it opportunistically; providers that don't support it should ignore or error
    # and RF4 will surface that message.
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_msg},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.2,
    }

    # Try to enable JSON mode if provider supports it
    try:
        payload["response_format"] = {"type": "json_object"}
    except Exception:
        pass

    try:
        resp = requests.post(url, headers=headers, data=json.dumps(payload), timeout=120)
    except Exception as e:
        return False, f"request failed: {e}"

    if resp.status_code // 100 != 2:
        # Include a small snippet of resp.text for debugging
        snippet = (resp.text or "")[:400]
        return False, f"http {resp.status_code}: {snippet}"

    try:
        data = resp.json()
        content = (
            data.get("choices", [{}])[0]
            .get("message", {})
            .get("content", "")
        )
    except Exception as e:
        return False, f"invalid response JSON: {e}"

    if not content or not isinstance(content, str):
        return False, "empty assistant content"

    try:
        out_path.write_text(content, encoding="utf-8")
    except Exception as e:
        return False, f"failed to write out_spec: {e}"

    return True, "ok"
