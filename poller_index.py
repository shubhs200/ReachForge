from __future__ import annotations

"""
Generic poller summarizer for ReachForge4.

Goal: Extract high-signal cues from <root>/poller/poller.py to bias both:
- Driver generation (single-shot, library/API path rather than server)
- Seeds generation (payload shapes, endpoints/topics, content-types, QoS, etc.)

We intentionally avoid hardcoding to specific libraries. Instead, we use heuristics:
- HTTP-style interactions (requests, aiohttp, flask test client, raw sockets with HTTP verbs)
- Multipart/form-data patterns, boundaries, content-disposition
- MQTT-style interactions (CONNECT/SUBSCRIBE/PUBLISH/PINGREQ, topics, QoS, bytes frames)
- Generic constants and small payload literals

Output: a compact textual summary suitable for inclusion in prompts.
"""

from pathlib import Path
import re
from typing import List


def _read_text(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def _clip(s: str, max_len: int = 800) -> str:
    if len(s) <= max_len:
        return s
    return s[: max_len] + "... (clipped)"


def _find_http_requests(text: str) -> List[str]:
    lines: List[str] = []

    # Common client libs patterns: requests, aiohttp client, httpx
    # requests.post("http://.../path", headers=..., files=..., data=..., json=...)
    req_re = re.compile(
        r"""\brequests\.(get|post|put|delete|patch)\s*\(\s*["']([^"']+)["']\s*(?:,([^)]*))?\)""",
        re.I | re.M,
    )
    for m in req_re.finditer(text):
        method = m.group(1).upper()
        url = m.group(2)
        args = (m.group(3) or "").strip().replace("\n", " ")
        lines.append(f"- HTTP {method} {url} args={{ {args} }}")

    # aiohttp client: session.post("http://.../path", ...)
    aio_re = re.compile(
        r"""\b(session|client)\.(get|post|put|delete|patch)\s*\(\s*["']([^"']+)["']\s*(?:,([^)]*))?\)""",
        re.I | re.M,
    )
    for m in aio_re.finditer(text):
        method = m.group(2).upper()
        url = m.group(3)
        args = (m.group(4) or "").strip().replace("\n", " ")
        lines.append(f"- HTTP {method} {url} args={{ {args} }} (aiohttp/httpx-like)")

    # Raw HTTP verbs in strings
    verb_re = re.compile(r'["\'](GET|POST|PUT|DELETE|PATCH)\s+/[^\s]*\s+HTTP/1\.[01]["\']', re.I)
    for m in verb_re.finditer(text):
        lines.append(f"- Raw HTTP verb snippet: {m.group(0)}")

    # Content-Type and multipart hints
    ct_re = re.compile(r'["\']Content-Type["\']\s*:\s*["\']([^"\']+)["\']', re.I)
    cts = set(m.group(1) for m in ct_re.finditer(text))
    for ct in cts:
        lines.append(f"- Header Content-Type: {ct}")

    # Multipart boundary references
    boundary_re = re.compile(r'boundary=([A-Za-z0-9._-]+)')
    for m in boundary_re.finditer(text):
        lines.append(f"- Multipart boundary token: {m.group(1)}")

    # Files= payloads in requests
    files_re = re.compile(r'\bfiles\s*=\s*\{([^}]+)\}', re.I | re.S)
    for m in files_re.finditer(text):
        lines.append(f"- files payload: {{{_clip(m.group(1), 200)}}}")

    # Data/json payloads
    data_re = re.compile(r'\bdata\s*=\s*({[^}]+}|["\'][^"\']+["\'])', re.I | re.S)
    for m in data_re.finditer(text):
        lines.append(f"- data payload: { _clip(m.group(1), 200) }")

    json_re = re.compile(r'\bjson\s*=\s*({[^}]+})', re.I | re.S)
    for m in json_re.finditer(text):
        lines.append(f"- json payload: { _clip(m.group(1), 200) }")

    return lines


def _find_multipart_hints(text: str) -> List[str]:
    lines: List[str] = []
    # Look for multipart form-data assembly
    multipart_re = re.compile(r"multipart/form-data", re.I)
    if multipart_re.search(text):
        lines.append("- Multipart form-data detected")
    disp_re = re.compile(r'Content-Disposition\s*:\s*form-data;[^"\n]*name=["\']?([^"\';]+)["\']?', re.I)
    for m in disp_re.finditer(text):
        lines.append(f"- Content-Disposition name: {m.group(1)}")
    fn_re = re.compile(r'filename=["\']?([^"\';]+)["\']?', re.I)
    for m in fn_re.finditer(text):
        lines.append(f"- Content-Disposition filename: {m.group(1)}")
    return lines


def _find_mqtt_patterns(text: str) -> List[str]:
    lines: List[str] = []
    # Keywords for MQTT operations
    for kw in ["CONNECT", "SUBSCRIBE", "UNSUBSCRIBE", "PUBLISH", "PINGREQ", "PINGRESP", "DISCONNECT"]:
        if re.search(rf"\b{kw}\b", text, re.I):
            lines.append(f"- MQTT op mentioned: {kw}")

    # Topics and QoS
    topic_re = re.compile(r'["\']([^"\']+/[^"\']+)["\']')  # simplistic: something/with/slash
    for m in topic_re.finditer(text):
        val = m.group(1)
        if "/" in val and len(val) <= 100:
            lines.append(f"- MQTT topic candidate: {val}")

    qos_re = re.compile(r'\bqos\s*=\s*([012])\b', re.I)
    for m in qos_re.finditer(text):
        lines.append(f"- MQTT QoS: {m.group(1)}")

    # Byte-like MQTT frames (very heuristic)
    # e.g., b"\x10\xxx..." (CONNECT), b"\x82..." (SUBSCRIBE), b"\x30..." (PUBLISH)
    bytes_re = re.compile(r'b["\']((?:\\x[0-9a-fA-F]{2}){2,})["\']')
    for m in bytes_re.finditer(text):
        seq = m.group(1)
        lines.append(f"- MQTT byte sequence: { _clip(seq, 80) }")

    return lines


def _find_generic_constants(text: str) -> List[str]:
    lines: List[str] = []
    # Headers and content-type literals
    hdr_re = re.compile(r'["\']([A-Za-z0-9-]+)\s*:\s*[^"\']+["\']')
    for m in hdr_re.finditer(text):
        s = m.group(0)
        if len(s) <= 120:
            lines.append(f"- Header literal: {s}")

    # Filenames and extensions
    ext_re = re.compile(r'["\']([^"\']+\.(?:png|jpg|jpeg|gif|tiff|bmp|jp2|j2k))["\']', re.I)
    for m in ext_re.finditer(text):
        lines.append(f"- Filename literal: {m.group(1)}")
    return lines


def _is_probably_text(p: Path, sniff_bytes: int = 4096) -> bool:
    try:
        b = p.read_bytes()[:sniff_bytes]
        # If it contains a NUL byte, likely binary
        if b"\x00" in b:
            return False
        # Try decode as utf-8 ignoring errors; if most bytes survive, call it text
        t = b.decode("utf-8", errors="ignore")
        return len(t.strip()) > 0
    except Exception:
        return False


def _preview_file(p: Path, max_text: int = 300, max_hex: int = 64) -> str:
    try:
        if _is_probably_text(p):
            t = p.read_text(encoding="utf-8", errors="ignore")
            t = t.replace("\r\n", "\n")
            return f"text:{_clip(t, max_text)}"
        else:
            b = p.read_bytes()[:max_hex]
            hexbytes = " ".join(f"{x:02x}" for x in b)
            return f"hex:{hexbytes}{' ...' if p.stat().st_size > max_hex else ''}"
    except Exception:
        return "unreadable"


def _collect_sample_inputs(root: Path, limit: int = 12) -> List[str]:
    """
    Recursively scan poller/ for files (excluding poller.py) and return summary lines.
    Useful when poller contains example inputs instead of a Python script.
    """
    base = (root / "poller").resolve()
    lines: List[str] = []
    if not base.exists() or not base.is_dir():
        return lines
    count = 0
    for p in sorted(base.rglob("*")):
        if not p.is_file():
            continue
        # Skip the script itself, dockerfiles, obvious build artifacts
        name_low = p.name.lower()
        if name_low in ("poller.py",) or name_low.endswith((".pyc", ".pyo")):
            continue
        if name_low.startswith("dockerfile") or name_low.endswith((".log", ".tmp")):
            continue
        try:
            rel = p.relative_to(root)
        except Exception:
            rel = p
        try:
            size = p.stat().st_size
        except Exception:
            size = -1
        preview = _preview_file(p)
        lines.append(f"- sample: {rel} (bytes={size}) preview={preview}")
        count += 1
        if count >= limit:
            break
    return lines


def build_poller_summary(root: Path, *, max_len: int = 1600) -> str:
    """
    Return a compact textual summary of poller interactions if poller/poller.py exists,
    else return empty string.
    """
    root = root.resolve()
    p = root / "poller" / "poller.py"
    text = _read_text(p) if p.exists() else ""

    lines: List[str] = []
    lines.append("Poller insights (derived heuristically from poller/):")

    http_lines = _find_http_requests(text)
    if http_lines:
        lines.append("HTTP patterns:")
        lines.extend(http_lines)

    mp_lines = _find_multipart_hints(text)
    if mp_lines:
        lines.append("Multipart hints:")
        lines.extend(mp_lines)

    mqtt_lines = _find_mqtt_patterns(text)
    if mqtt_lines:
        lines.append("MQTT patterns:")
        lines.extend(mqtt_lines)

    gen_consts = _find_generic_constants(text)
    if gen_consts:
        lines.append("Generic constants:")
        lines.extend(gen_consts)

    # If there are sample input files under poller/, surface a few with previews
    sample_lines = _collect_sample_inputs(root)
    if sample_lines:
        lines.append("Sample inputs under poller/:")
        lines.extend(sample_lines)

    if len(lines) == 1:
        return ""
    summary = "\n".join(lines)
    return _clip(summary, max_len)


__all__ = ["build_poller_summary"]
