from __future__ import annotations

import json
from importlib.util import spec_from_file_location, module_from_spec
from pathlib import Path
from typing import Optional, Tuple


def _run_shell(cmd: str, cwd: Path) -> Tuple[int, str, str]:
    import subprocess
    p = subprocess.run(cmd, shell=True, cwd=str(cwd), text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return p.returncode, p.stdout, p.stderr


def _load_compile_cmd_template(app_root: Path, app_name: str) -> Optional[str]:
    """
    Resolve compile command template, preferring the bundled reachforge4/config/compile_command.py,
    then falling back to ReachForge/config/compile_command.py (legacy).
    """
    candidates = [
        Path(__file__).parent / "config" / "compile_command.py",
        Path("ReachForge/config/compile_command.py"),
    ]
    for cfg_path in candidates:
        if not cfg_path.exists():
            continue
        try:
            spec = spec_from_file_location("rf_compile_cfg", str(cfg_path))
            assert spec and spec.loader
            mod = module_from_spec(spec)
            spec.loader.exec_module(mod)  # type: ignore[attr-defined]
            if hasattr(mod, "generate_compile_cmd_template"):
                try:
                    return mod.generate_compile_cmd_template(app_root=str(app_root), app_name=app_name)
                except TypeError:
                    return mod.generate_compile_cmd_template()
        except Exception:
            continue
    return None


def _choose_source_root(app_root: Path) -> Path:
    app_src = app_root / "app" / "src"
    src = app_root / "src"
    return app_src if app_src.exists() else (src if src.exists() else app_root)


def compile_driver(app_root: Path, app_name: str, *, src_path: Path, binary_path: Path, out_dir: Path, workdir: Optional[Path] = None, extra_sources: Optional[list[str]] = None) -> Tuple[bool, str]:
    """
    Compile a single driver source using the per-app compile template if available.
      - Fills placeholders: {src}, {binary}, {harness_dir}, {name}, {lang}, {cmake_snippet}, {out_dir}, {workdir}
    Returns (ok, message).
    """
    app_root = app_root.resolve()
    out_dir = out_dir.resolve()
    workdir = (workdir or app_root).resolve()
    src_path = src_path.resolve()
    binary_path = binary_path.resolve()
    binary_path.parent.mkdir(parents=True, exist_ok=True)

    tmpl = _load_compile_cmd_template(app_root, app_name)
    if not tmpl:
        return False, "No compile template found at ReachForge/config/compile_command.py"

    # Expand sources: primary src + any extra_sources from spec (robust path resolution)
    extras_list = list(extra_sources or [])
    extras_paths: list[str] = []
    src_root = _choose_source_root(app_root)
    for rel in extras_list:
        try:
            p = Path(rel)
            cand = None
            if p.is_absolute():
                cand = p if p.exists() else None
            else:
                p1 = app_root / rel
                if p1.exists():
                    cand = p1
                else:
                    p2 = src_root / rel
                    if p2.exists():
                        cand = p2
                    else:
                        # search by basename under source root
                        name = p.name
                        for q in src_root.rglob(name):
                            if q.is_file():
                                cand = q
                                break
            if cand and cand.is_file():
                sp = str(cand.resolve())
                if sp not in extras_paths:
                    extras_paths.append(sp)
        except Exception:
            continue
    srcs_str = " ".join([str(src_path)] + extras_paths) if extras_paths else str(src_path)

    # Fill placeholders
    filled = (
        tmpl.replace("{src}", srcs_str)
            .replace("{binary}", str(binary_path))
            .replace("{harness_dir}", str(src_path.parent))
            .replace("{name}", binary_path.name)
            .replace("{lang}", "c" if src_path.suffix == ".c" else "c++")
            .replace("{cmake_snippet}", "")
            .replace("{out_dir}", str(out_dir))
            .replace("{workdir}", str(workdir))
    )

    rc, so, se = _run_shell(filled, cwd=workdir)
    log = (out_dir / "compile.log.txt")
    log.write_text(f"CMD:\n{filled}\n\nEXIT: {rc}\n\nSTDOUT:\n{so}\n\nSTDERR:\n{se}\n", encoding="utf-8")

    if rc != 0 or not binary_path.exists():
        return False, f"compile failed (rc={rc}); see {log}"
    return True, f"ok; binary at {binary_path}"
