import json
import os
import time
from pathlib import Path
from typing import Optional, Tuple
import urllib.request
import urllib.error


def _read_text(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8")
    except Exception:
        return ""


def run_openai_json(prompt_path: Path, out_path: Path, *, model: str, api_base: Optional[str] = None, max_retries: int = 3) -> Tuple[bool, str]:
    """
    OpenAI ChatCompletion JSON wrapper using urllib (Python 3.5 compatible).
    Writes:
      - Assistant JSON output to out_path
      - Token usage sidecar to <out_path>.usage.json
    """

    prompt_path = Path(prompt_path)
    out_path = Path(out_path)
    # Don't resolve out_path - it may not exist yet
    out_path.parent.mkdir(parents=True, exist_ok=True)

    api_key = os.getenv("OPENAI_API_KEY") or os.getenv("OPENAI_API_TOKEN")
    if not api_key:
        return False, "missing OPENAI_API_KEY"

    base = (api_base or "https://api.openai.com/v1").rstrip("/")
    url = base + "/chat/completions"

    prompt = _read_text(prompt_path)
    if not prompt.strip():
        return False, "empty prompt"

    system_msg = (
        "You are a code generator that must output ONLY a single JSON object "
        "with no code fences and no prose."
    )

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_msg},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.2,
        "response_format": {"type": "json_object"},
    }

    headers = {
        "Authorization": "Bearer " + api_key,
        "Content-Type": "application/json",
    }

    last_error = None
    for attempt in range(max_retries):
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers=headers,
                method="POST"
            )
            resp = urllib.request.urlopen(req, timeout=180)
            data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            snippet = ""
            try:
                snippet = e.read().decode("utf-8")[:400]
            except Exception:
                pass
            if e.code == 429:  # Rate limited
                last_error = "rate limited (attempt " + str(attempt+1) + "/" + str(max_retries) + ")"
                print("Warning: " + last_error)
                if attempt < max_retries - 1:
                    wait_time = 30
                    print("Waiting " + str(wait_time) + " seconds for rate limit...")
                    time.sleep(wait_time)
                    continue
            return False, "http " + str(e.code) + ": " + snippet
        except urllib.error.URLError as e:
            last_error = "connection error (attempt " + str(attempt+1) + "/" + str(max_retries) + "): " + str(e.reason)
            print("Warning: " + last_error)
            if attempt < max_retries - 1:
                wait_time = (attempt + 1) * 5
                print("Retrying in " + str(wait_time) + " seconds...")
                time.sleep(wait_time)
                continue
            return False, last_error
        except Exception as e:
            return False, "request failed: " + str(e)

        break  # Success

    try:
        content = (
            data.get("choices", [{}])[0]
            .get("message", {})
            .get("content", "")
        )
    except Exception:
        content = ""

    if not content or not isinstance(content, str):
        return False, "empty assistant content"

    # ---- Extract token usage safely ----
    usage = data.get("usage") if isinstance(data, dict) else {}

    prompt_tokens = int(usage.get("prompt_tokens", 0)) if usage else 0
    completion_tokens = int(usage.get("completion_tokens", 0)) if usage else 0
    total_tokens = int(usage.get("total_tokens", 0)) if usage else (prompt_tokens + completion_tokens)

    usage_meta = {
        "model": data.get("model") or model,
        "id": data.get("id"),
        "created": data.get("created"),
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": total_tokens,
        },
    }

    # Always write usage file (even if zeros)
    try:
        usage_path = out_path.with_name(out_path.name + ".usage.json")
        usage_path.write_text(json.dumps(usage_meta, indent=2), encoding="utf-8")
    except Exception:
        pass  # never fail generation due to usage writing

    try:
        out_path.write_text(content.strip(), encoding="utf-8")
    except Exception as e:
        return False, "failed to write out_spec: " + str(e)

    return True, "ok"


def run_openai_code(prompt_path, out_path, model, api_base=None, max_retries=3):
    """
    OpenAI ChatCompletion wrapper for code generation (no JSON mode).
    Identical to run_openai_json but uses a code-oriented system prompt
    and does not enforce response_format, so the LLM can return plain code.
    """
    prompt_path = Path(prompt_path)
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    api_key = os.getenv("OPENAI_API_KEY") or os.getenv("OPENAI_API_TOKEN")
    if not api_key:
        return False, "missing OPENAI_API_KEY"

    base = (api_base or "https://api.openai.com/v1").rstrip("/")
    url = base + "/chat/completions"

    prompt = _read_text(prompt_path)
    if not prompt.strip():
        return False, "empty prompt"

    system_msg = (
        "You are an expert Python programmer. Output ONLY a complete, "
        "self-contained Python 3 script with no prose, no explanations, "
        "and no markdown fences. The script must be directly executable."
    )

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_msg},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.2,
    }

    headers = {
        "Authorization": "Bearer " + api_key,
        "Content-Type": "application/json",
    }

    last_error = None
    for attempt in range(max_retries):
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers=headers,
                method="POST"
            )
            resp = urllib.request.urlopen(req, timeout=180)
            data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            snippet = ""
            try:
                snippet = e.read().decode("utf-8")[:400]
            except Exception:
                pass
            if e.code == 429:
                last_error = "rate limited (attempt " + str(attempt+1) + "/" + str(max_retries) + ")"
                print("Warning: " + last_error)
                if attempt < max_retries - 1:
                    time.sleep(30)
                    continue
            return False, "http " + str(e.code) + ": " + snippet
        except urllib.error.URLError as e:
            last_error = "connection error (attempt " + str(attempt+1) + "/" + str(max_retries) + "): " + str(e.reason)
            print("Warning: " + last_error)
            if attempt < max_retries - 1:
                time.sleep((attempt + 1) * 5)
                continue
            return False, last_error
        except Exception as e:
            return False, "request failed: " + str(e)
        break

    try:
        content = (
            data.get("choices", [{}])[0]
            .get("message", {})
            .get("content", "")
        )
    except Exception:
        content = ""

    if not content or not isinstance(content, str):
        return False, "empty assistant content"

    # Save token usage
    usage = data.get("usage") if isinstance(data, dict) else {}
    prompt_tokens = int(usage.get("prompt_tokens", 0)) if usage else 0
    completion_tokens = int(usage.get("completion_tokens", 0)) if usage else 0
    total_tokens = int(usage.get("total_tokens", 0)) if usage else (prompt_tokens + completion_tokens)
    try:
        usage_path = out_path.with_name(out_path.name + ".usage.json")
        usage_path.write_text(json.dumps({
            "model": data.get("model") or model,
            "id": data.get("id"),
            "created": data.get("created"),
            "usage": {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": total_tokens,
            },
        }, indent=2), encoding="utf-8")
    except Exception:
        pass

    try:
        out_path.write_text(content.strip(), encoding="utf-8")
    except Exception as e:
        return False, "failed to write output: " + str(e)

    return True, "ok"