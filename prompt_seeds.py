from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from reachforge.seeds_schema import SEEDS_SPEC_SCHEMA
from reachforge.poller_index import build_poller_summary


def _load_vulns(root: Path) -> list[dict]:
    # Search for vulnerabilities.json starting at root and walking up parents,
    # supporting layouts where the app root is a subdir of the repo.
    candidates = []
    cur = root
    for cur in [cur, *cur.parents]:
        candidates.append(cur / "vulnerabilities.json")
        candidates.append(cur / "app" / "vulnerabilities.json")

    for p in candidates:
        if p.exists():
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                return data.get("vulnerabilities", [])
            except Exception:
                return []
    return []


def _load_driver_spec(out_dir: Path) -> Optional[dict]:
    try:
        specp = out_dir / "specs" / "driver_spec.json"
        if not specp.exists():
            return None
        return json.loads(specp.read_text(encoding="utf-8"))
    except Exception:
        return None


def build_seeds_prompt(root: Path, out_dir: Path, *, include_poller: bool = True) -> Optional[Path]:
    """
    Build a prompt that instructs the LLM to output a SeedsSpec JSON ONLY (no prose).
    Uses vulnerabilities.json and the generated DriverSpec to provide context.
    Returns the prompt path, or None if prerequisites are missing.
    """
    root = root.resolve()
    out_dir = out_dir.resolve()

    # Require a valid DriverSpec to extract input mode and simple hints
    dspec = _load_driver_spec(out_dir)
    if dspec is None:
        return None

    # Harness input mode: infer from driver content (buffer by default)
    # We keep v1 simple: default to buffer, nudge to file if poller suggests multipart
    harness_mode = "buffer"
    driver_source = dspec.get("driver_source", "")

    vulns = _load_vulns(root)
    vulns_subset = []
    for v in vulns[:12]:
        vulns_subset.append({
            "cve": v.get("cve-id"),
            "cwe": v.get("cwe-id"),
            "cwe_name": v.get("cwe-name"),
            "affected_function": v.get("affected-function"),
            "affected_file": v.get("affected-file"),
            "expected_format": v.get("input-format") or v.get("format") or v.get("protocol"),
        })

    # Poller insights (optional)
    poller_blob = ""
    if include_poller:
        try:
            poller_blob = build_poller_summary(root)
        except Exception:
            poller_blob = ""
        # Heuristic: if poller mentions multipart/form-data, suggest file mode
        if poller_blob and ("multipart/form-data" in poller_blob.lower() or "multipart" in poller_blob.lower()):
            harness_mode = "file"

    lines: list[str] = []
    if poller_blob:
        lines.append("Poller insights (from poller/poller.py):")
        lines.append(poller_blob)
        lines.append("Use these patterns to shape 10 realistic seeds (keep them small and diverse).")
        lines.append("")
    lines.append("You are given a fuzz harness that consumes input in a single-shot, deterministic manner.")
    lines.append(
        "Task: Output ONLY a SeedsSpec JSON with EXACTLY 10 seeds. Every seed MUST target one or more vulnerabilities described in vulnerabilities.json; "
        "do NOT create seeds for formats, protocols, or code paths that are not associated with any listed vulnerability."
    )
    lines.append("Do NOT include code fences or any prose beyond the SeedsSpec JSON itself.")
    lines.append("")
    lines.append("SeedsSpec JSON schema (reminder; follow strictly):")
    lines.append(json.dumps(SEEDS_SPEC_SCHEMA, indent=2))
    lines.append("")
    lines.append("Constraints:")
    lines.append("- 'seeds' must contain exactly 10 items.")
    lines.append("- Each seed has: filename (string), encoding (hex|base64|utf8), content (string), optional notes (string).")
    lines.append("- Keep seeds small; prefer <= 4 KiB each unless strictly necessary; include 'max_size_bytes' if helpful.")
    lines.append(f"- 'harness_input_mode' should match how the harness reads input (suggested: {harness_mode}).")
    lines.append("- Do NOT reference unavailable files or resources; all seed content must be fully provided in the JSON.")
    lines.append("")
    if vulns_subset:
        lines.append("Vulnerabilities (subset):")
        lines.append(json.dumps(vulns_subset, indent=2))
        lines.append("")
        lines.append("Guidance:")
        lines.append(
            "- Start from inputs that would be well-formed or realistic for the vulnerable format/subsystem, "
            "then apply minimal, targeted corruptions in the fields that drive the vulnerable behavior "
            "(sizes, counts, indexes, offsets, chunk lengths, etc.)."
        )
        lines.append(
            "- Derive tokens/fields/lengths directly from the affected functions/files and their expected structures. "
            "Prefer seeds that are valid-ish and get as deep as possible into parsing before failing."
        )
        lines.append(
            "- Include boundary conditions closely tied to the vulnerabilities: values just below/above limits, "
            "off-by-one sizes, near-overflow lengths, minimal/maximal topic or field sizes, etc."
        )
        lines.append(
            "- Cover a variety of control paths within the vulnerable components only (for example, multiple RAW/CR2 variants "
            "for LibRaw or different chunk layouts for a single image format), not unrelated formats or protocols."
        )
        lines.append("Mandatory vulnerability alignment:")
        lines.append(
            "- Produce seeds that explicitly target the functions/files listed above. For example, if a vulnerability "
            "describes RAW/CR2 processing in a LibRaw entry, use RAW/CR2-like inputs that exercise that code path; if it "
            "describes a WebP decoder function, use WebP-like frames."
        )
        lines.append(
            "- Each seed must conform to the expected input format listed in vulnerabilities.json (via its input-format/format/protocol "
            "fields, or as implied by the description), rather than inventing unrelated formats."
        )
        lines.append(
            "- Generate at least one seed per vulnerability entry and reference the corresponding CVE/CWE and expected_format "
            "in each seed's 'notes' field."
        )
        lines.append(
            "- Shape headers/magic bytes/metadata so that the vulnerable functions are exercised as directly as possible; "
            "bias field lengths and chunk layouts toward the affected code paths."
        )
        lines.append(
            "- When a vulnerability references specific structures (such as particular tags, chunks, or color planes), "
            "mirror those details in the seed content as closely as possible."
        )
        lines.append(
            "- Avoid obviously invalid garbage blobs (wrong magic, impossible top-level sizes) unless the vulnerability "
            "explicitly concerns such cases; prefer \"almost valid\" inputs with small, targeted corruptions."
        )
        lines.append(
            "- If the application supports many formats or subsystems, but vulnerabilities.json names only a subset, "
            "then generate seeds ONLY for the vulnerable formats/subsystems; do NOT include seeds for non-vulnerable handlers."
        )

        app_name = root.name
        if app_name == "image-histogram":
            lines.append("Image-histogram specific guidance:")
            lines.append(
                "- Prioritize the first vulnerability (LibRaw RAW processing in raw2image_ex on Canon-style CR2 inputs). "
                "Most seeds should be Canon CR2-like RAW images that look structurally valid but carry slightly malformed "
                "size/pitch or row-stride metadata to stress memmove-based row copying."
            )
            lines.append(
                "- Canon CR2 is a TIFF-based RAW format that typically starts with a little-endian TIFF header, "
                "followed by a 'CR2' marker and EXIF-style tags (such as date/time and camera make/model). Shape seeds "
                "to preserve this overall layout while varying the dimensions and pitch-related fields."
            )
            lines.append(
                "- Focus your 10 seeds on RAW/CR2-style inputs that reach LibRaw's raw2image_ex path quickly, instead of "
                "inventing seeds for unrelated image formats that are not described by any vulnerability entry."
            )
    else:
        lines.append("No vulnerabilities.json found; still produce 10 diverse seeds that exercise parsing.")
    lines.append("")
    lines.append("Harness hints (short excerpt from driver):")
    excerpt = "\n".join(driver_source.splitlines()[:80])
    lines.append(excerpt if excerpt else "// no excerpt available")
    lines.append("")
    lines.append("Now output ONLY the SeedsSpec JSON.")

    ctx_dir = out_dir / "context"
    ctx_dir.mkdir(parents=True, exist_ok=True)
    prompt_path = ctx_dir / "prompt.seeds.md"
    prompt_path.write_text("\n".join(lines), encoding="utf-8")
    return prompt_path
