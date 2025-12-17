# User-editable compile command template for building the fuzz driver.
# This file is bundled with reachforge4 so CI pipelines don't need ReachForge/config.
# Edit generate_compile_cmd_template() to match your project's include/lib paths
# and instrumentation (e.g., AFL++ + ASAN). The placeholders below will be
# substituted by ReachForge4:
#   {src}           -> generated harness source path(s)
#   {binary}        -> output binary path
#   {harness_dir}   -> harness directory
#   {name}          -> harness target name (default: fuzz_driver)
#   {lang}          -> "c" or "c++"
#   {cmake_snippet} -> CMake snippet path (unused here)
#   {out_dir}       -> output directory
#   {workdir}       -> working directory used to run the compile command
#
# Note: The command runs under `bash -lc "...` so you may export CC/CXX and flags inline.


# Per-application compile command selector. The tool will pass (app_root, app_name)
# so we can pick a compile recipe without hardcoding inside the tool.
# Placeholders are replaced by ReachForge4:
#   {src} {binary} {harness_dir} {name} {lang} {cmake_snippet} {out_dir} {workdir}

APP_RULES = {
    # mqtt-server (mongoose)
    "mqtt-server": (
        'bash -lc "AFL_USE_ASAN=1 '
        'afl-clang -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer '
        '-I mqtt-server/app/src '
        '-I /home/shubham/ReachForge/mqtt-server/build/vcpkg_installed/x64-linux-cromulence/include '
        '{src} '
        '-o {binary} '
        '/home/shubham/ReachForge/mqtt-server/build/vcpkg_installed/x64-linux-cromulence/lib/libmongoose.a '
        '-lpthread -lm"'
    ),

    # analyze-image
    "analyze-image": (
        'bash -lc "AFL_USE_ASAN=1 '
        'afl-clang -g -O0 -fno-omit-frame-pointer -fsanitize=address,undefined '
        '-I. -Iapp/src -Ibuild/vcpkg_installed/x64-linux-ellf/include '
        '{src} '
        '-o {binary} '
        'build/vcpkg_installed/x64-linux-ellf/lib/libturbojpeg.a '
        'build/vcpkg_installed/x64-linux-ellf/lib/libtiff.a '
        'build/vcpkg_installed/x64-linux-ellf/lib/libopenjp2.a '
        'build/vcpkg_installed/x64-linux-ellf/lib/libjpeg.a '
        'build/vcpkg_installed/x64-linux-ellf/lib/libz.a '
        'build/vcpkg_installed/x64-linux-ellf/lib/libmicrohttpd.a '
        'build/vcpkg_installed/x64-linux-ellf/lib/libpng16.a '
        'build/vcpkg_installed/x64-linux-ellf/lib/liblzma.a '
        'build/vcpkg_installed/x64-linux-ellf/lib/libgif.a '
        '-lm -ldl -lpthread"'
    ),

    # challenge
    "challenge": (
        'bash -lc "AFL_USE_ASAN=1 '
        'afl-clang -g -O0 -fno-omit-frame-pointer -fsanitize=address,undefined '
        '-I. -Iapp/src -Ibuild-artifacts/challenge/build/vcpkg_installed/x64-linux-ellf/include '
        '{src} '
        '-o {binary} '
        '-Wl,--start-group '
        'build-artifacts/challenge/build/vcpkg_installed/x64-linux-ellf/lib/libturbojpeg.a '
        'build-artifacts/challenge/build/vcpkg_installed/x64-linux-ellf/lib/libtiff.a '
        'build-artifacts/challenge/build/vcpkg_installed/x64-linux-ellf/lib/libopenjp2.a '
        'build-artifacts/challenge/build/vcpkg_installed/x64-linux-ellf/lib/libjpeg.a '
        'build-artifacts/challenge/build/vcpkg_installed/x64-linux-ellf/lib/libpng16.a '
        'build-artifacts/challenge/build/vcpkg_installed/x64-linux-ellf/lib/libwebp.a '
        'build-artifacts/challenge/build/vcpkg_installed/x64-linux-ellf/lib/libgif.a '
        'build-artifacts/challenge/build/vcpkg_installed/x64-linux-ellf/lib/libraw_r.a '
        'build-artifacts/challenge/build/vcpkg_installed/x64-linux-ellf/lib/libmagic.a '
        'build-artifacts/challenge/build/vcpkg_installed/x64-linux-ellf/lib/libjasper.a '
        'build-artifacts/challenge/build/vcpkg_installed/x64-linux-ellf/lib/liblcms2.a '
        'build-artifacts/challenge/build/vcpkg_installed/x64-linux-ellf/lib/libz.a '
        'build-artifacts/challenge/build/vcpkg_installed/x64-linux-ellf/lib/liblzma.a '
        '-Wl,--end-group '
        '-lstdc++ -lm -ldl -lpthread"'
    ),

"lamartine": (
    'bash -lc "AFL_USE_ASAN=1 CXX=afl-clang++ '
    'afl-clang++ -std=c++20 -g -O1 -fsanitize=address,undefined '
    '-fno-omit-frame-pointer -fuse-ld=lld '
    '-DASIO_NO_DEPRECATED -DASIO_STANDALONE -DHELLO_THERE '
    '-I. -Isrc -Isrc/doom -Isrc/tpl '
    '-I ../../build-artifacts/challenge/build/vcpkg_installed/x64-linux-ellf/include '
    '-I ../../build-artifacts/challenge/build/vcpkg_installed/x64-linux-ellf/include/crow '
    '-I ../../build-artifacts/challenge/build/vcpkg_installed/x64-linux-ellf/include/libxml2 '
    '-o {binary} {src} '
    'src/assert.cpp src/base64.cpp src/error_processor.cpp src/session.cpp src/share_finder.cpp '
    'src/util_env.cpp src/util_rand.cpp src/var_finder.cpp src/watcher.cpp '
    'src/doom/classic_reader.cpp src/doom/digger.cpp '
    'src/doom/map.cpp src/doom/pwad.cpp src/doom/svg_writer.cpp src/doom/udmf_parser.cpp '
    'src/tpl/base.cpp src/tpl/index.cpp src/tpl/map.cpp src/tpl/upload.cpp '
    '../../build-artifacts/challenge/build/vcpkg_installed/x64-linux-ellf/lib/libsodium.a '
    '../../build-artifacts/challenge/build/vcpkg_installed/x64-linux-ellf/lib/libxml2.a '
    '../../build-artifacts/challenge/build/vcpkg_installed/x64-linux-ellf/lib/libmagic.a '
    '../../build-artifacts/challenge/build/vcpkg_installed/x64-linux-ellf/lib/libzip.a '
    '../../build-artifacts/challenge/build/vcpkg_installed/x64-linux-ellf/lib/libz.a '
    '../../build-artifacts/challenge/build/vcpkg_installed/x64-linux-ellf/lib/libbz2.a '
    '../../build-artifacts/challenge/build/vcpkg_installed/x64-linux-ellf/lib/libcrypto.a '
    '../../build-artifacts/challenge/build/vcpkg_installed/x64-linux-ellf/lib/libssl.a '
    '../../build-artifacts/challenge/build/vcpkg_installed/x64-linux-ellf/lib/liblzma.a '
    '-ldl -lm"'
    ),


    # cjson
    "cjson": (
        'bash -lc "AFL_USE_ASAN=1 '
        'afl-clang -std=c11 -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer '
        '-I. '
        '-o {binary} {src} '
        'cJSON.c cJSON_Utils.c"'
    ),
    "redis": (
    'bash -lc "AFL_USE_ASAN=1 '
    'afl-clang -g3 -O1 -fno-omit-frame-pointer -fsanitize=address,undefined '
    '-I. -Isrc '
    '-Ideps/fast_float '
    '-Ideps/fpconv '
    '-Ideps/linenoise '
    '-Ibuild-artifacts/vcpkg_installed/x64-linux-ellf/include '
    '-Ibuild-artifacts/vcpkg_installed/x64-linux-ellf/include/hdr '
    '-Ibuild-artifacts/vcpkg_installed/x64-linux-ellf/include/hiredis '
    '{src} '
    '-o {binary} '
    '-Lbuild-artifacts/vcpkg_installed/x64-linux-ellf/lib '
    '-llua -lm -ldl -lpthread"'
    ),

   "cfs-eval2": (
    'bash -lc "'
    'afl-clang -fsanitize=address -g -O1 -fno-omit-frame-pointer '
    '-Ibuild-artifacts/cfs/buildtrees/mm/src/d31fe7a035-523bcc0982.clean/fsw/inc '
    '-Ibuild-artifacts/cfs/buildtrees/mm/src/d31fe7a035-523bcc0982.clean/fsw/src '
    '-Ibuild-artifacts/cfs/buildtrees/cfs/cfs-src/cfe/modules/core_api/fsw/inc '
    '-Ibuild-artifacts/cfs/buildtrees/cfs/cfs-src/cfe/modules/core_private/fsw/inc '
    '-Ibuild-artifacts/cfs/buildtrees/cfs/cfs-src/cfe/modules/msg/fsw/inc '
    '-Ibuild-artifacts/cfs/buildtrees/cfs/cfs-src/cfe/modules/msg/option_inc '
    '-Ibuild-artifacts/cfs/buildtrees/cfs/cfs-src/osal/src/os/inc '
    '-Ibuild-artifacts/cfs/buildtrees/cfs/cfs-src/psp/fsw/inc '

    '-Ibuild-artifacts/cfs/buildtrees/cfs/cfs-src/cfe/build/inc '
    '-Ibuild-artifacts/cfs/buildtrees/cfs/cfs-src/cfe/build/custom/default_cpu1/inc '
    '-Ibuild-artifacts/cfs/buildtrees/cfs/cfs-src/cfe/build/custom/default_cpu1/osal/inc '

    '{src} '
    'build-artifacts/cfs/buildtrees/mm/src/d31fe7a035-523bcc0982.clean/fsw/src/mm_app.c '
    'build-artifacts/cfs/buildtrees/mm/src/d31fe7a035-523bcc0982.clean/fsw/src/mm_dump.c '
    'build-artifacts/cfs/buildtrees/mm/src/d31fe7a035-523bcc0982.clean/fsw/src/mm_load.c '
    'build-artifacts/cfs/buildtrees/mm/src/d31fe7a035-523bcc0982.clean/fsw/src/mm_utils.c '
    'build-artifacts/cfs/buildtrees/mm/src/d31fe7a035-523bcc0982.clean/fsw/src/mm_mem8.c '
    'build-artifacts/cfs/buildtrees/mm/src/d31fe7a035-523bcc0982.clean/fsw/src/mm_mem16.c '
    'build-artifacts/cfs/buildtrees/mm/src/d31fe7a035-523bcc0982.clean/fsw/src/mm_mem32.c '
    '-o {binary}"'
),

    "cfs": (
        'bash -lc "'
        'afl-clang -fsanitize=address -g -O1 -fno-omit-frame-pointer '
        '-Ibuild-artifacts/cfs/buildtrees/mm/src/d31fe7a035-523bcc0982.clean/fsw/inc '
        '-Ibuild-artifacts/cfs/buildtrees/mm/src/d31fe7a035-523bcc0982.clean/fsw/src '
        '-Ibuild-artifacts/cfs/buildtrees/cfs/cfs-src/cfe/modules/core_api/fsw/inc '
        '-Ibuild-artifacts/cfs/buildtrees/cfs/cfs-src/cfe/modules/core_private/fsw/inc '
        '-Ibuild-artifacts/cfs/buildtrees/cfs/cfs-src/cfe/modules/msg/fsw/inc '
        '-Ibuild-artifacts/cfs/buildtrees/cfs/cfs-src/cfe/modules/msg/option_inc '
        '-Ibuild-artifacts/cfs/buildtrees/cfs/cfs-src/osal/src/os/inc '
        '-Ibuild-artifacts/cfs/buildtrees/cfs/cfs-src/psp/fsw/inc '

        '-Ibuild-artifacts/cfs/buildtrees/cfs/cfs-src/cfe/build/inc '
        '-Ibuild-artifacts/cfs/buildtrees/cfs/cfs-src/cfe/build/custom/default_cpu1/inc '
        '-Ibuild-artifacts/cfs/buildtrees/cfs/cfs-src/cfe/build/custom/default_cpu1/osal/inc '

        '{src} '
        'build-artifacts/cfs/buildtrees/mm/src/d31fe7a035-523bcc0982.clean/fsw/src/mm_app.c '
        'build-artifacts/cfs/buildtrees/mm/src/d31fe7a035-523bcc0982.clean/fsw/src/mm_dump.c '
        'build-artifacts/cfs/buildtrees/mm/src/d31fe7a035-523bcc0982.clean/fsw/src/mm_load.c '
        'build-artifacts/cfs/buildtrees/mm/src/d31fe7a035-523bcc0982.clean/fsw/src/mm_utils.c '
        'build-artifacts/cfs/buildtrees/mm/src/d31fe7a035-523bcc0982.clean/fsw/src/mm_mem8.c '
        'build-artifacts/cfs/buildtrees/mm/src/d31fe7a035-523bcc0982.clean/fsw/src/mm_mem16.c '
        'build-artifacts/cfs/buildtrees/mm/src/d31fe7a035-523bcc0982.clean/fsw/src/mm_mem32.c '
        '-o {binary}"'
    )
}


def get_compile_cmd(app_root: str, app_name: str) -> str | None:
    return APP_RULES.get(app_name)


def _detect_app_name(app_root: str | None, app_name: str | None) -> str:
    """Best-effort logical app-name detection.

    Priority:
      1) REACHFORGE_APP_NAME env override
      2) Marker file in repo (.reachforge_app or reachforge_app_name.txt)
      3) Heuristics for known apps (redis, image-histogram, lamartine)
      4) CLI-provided app_name
      5) Directory basename
    """
    from pathlib import Path as _P
    import os as _os
    import json as _json

    ar = _P(app_root).resolve() if app_root else _P(".").resolve()

    # 1) Explicit environment override
    env_name = _os.getenv("REACHFORGE_APP_NAME")
    if env_name:
        env_name = env_name.strip()
        if env_name:
            return env_name

    # 2) Repository-local marker file
    for rel in (".reachforge_app", "reachforge_app_name.txt"):
        marker = ar / rel
        if marker.exists():
            try:
                text = marker.read_text(encoding="utf-8")
                first = (text.splitlines()[0] if text else "").strip()
            except Exception:
                first = ""
            if first:
                return first

    # 3) Heuristics for known apps
    # redis: redis-test.conf (or similar) at repo root
    if (ar / "redis-test.conf").exists() or (ar / "redis.conf").exists():
        return "redis"

    # image-histogram / challenge: ELLF image challenge with app/src/image.c
    # In the CI pipeline, the ELLF challenge layout uses build-artifacts/challenge/...
    # and historically used the "challenge" APP_RULE (with those paths). For a local
    # image-histogram repo (no build-artifacts/ tree), we instead use the
    # "image-histogram" rule that targets build/vcpkg_installed.
    if (ar / "app" / "src" / "image.c").exists():
        ba = ar / "build-artifacts" / "challenge" / "build" / "vcpkg_installed"
        if ba.exists():
            return "challenge"
        return "image-histogram"

    # lamartine: vcpkg.json mentioning lamartine, or characteristic doom sources
    vcpkg = ar / "vcpkg.json"
    if vcpkg.exists():
        try:
            cfg = _json.loads(vcpkg.read_text(encoding="utf-8"))
            name = str(cfg.get("name", "")).lower()
            if "lamartine" in name:
                return "lamartine"
        except Exception:
            pass
    if (ar / "src" / "doom" / "pwad.cpp").exists():
        return "lamartine"

    # 4) Fallbacks
    if app_name:
        return app_name

    return ar.name


def generate_compile_cmd_template(app_root: str | None = None, app_name: str | None = None) -> str:
    """Dynamic compile command template with vcpkg triplet auto-detection."""
    from pathlib import Path as _P

    ar = _P(app_root).resolve() if app_root else _P('.')

    def _pick_triplet(root: _P) -> str:
        candidates = ["x64-linux-ellf", "x64-linux-cromulence"]
        base = root / "build" / "vcpkg_installed"
        for t in candidates:
            if (base / t / "include").exists():
                return t
        return "x64-linux-ellf"

    resolved_name = _detect_app_name(app_root, app_name)

    # analyze-image and challenge handled by APP_RULES (legacy)
    if resolved_name in {"analyze-image", "challenge"}:
        return get_compile_cmd(app_root or "", resolved_name)

    # Dynamic rule for image-histogram
    if resolved_name == "image-histogram":
        trip = _pick_triplet(ar)
        inc = f"build/vcpkg_installed/{trip}/include"
        lib = f"build/vcpkg_installed/{trip}/lib"
        return (
            'bash -lc "AFL_USE_ASAN=1 '
            'afl-clang -g -O0 -fno-omit-frame-pointer -fsanitize=address,undefined '
            f'-I. -Iapp/src -I{inc} '
            '{src} app/src/image.c '
            '-o {binary} '
            '-Wl,--start-group '
            f'{lib}/libturbojpeg.a '
            f'{lib}/libtiff.a '
            f'{lib}/libopenjp2.a '
            f'{lib}/libjpeg.a '
            f'{lib}/libpng16.a '
            f'{lib}/libwebp.a '
            f'{lib}/libgif.a '
            f'{lib}/libraw_r.a '
            f'{lib}/libmagic.a '
            f'{lib}/libjasper.a '
            f'{lib}/liblcms2.a '
            f'{lib}/libz.a '
            f'{lib}/liblzma.a '
            '-Wl,--end-group '
            '-lstdc++ -lm -ldl -lpthread"'
        )

    # lamartine handled by APP_RULES
    if resolved_name == "lamartine":
        return get_compile_cmd(app_root or "", resolved_name)

    # fallback: try APP_RULES by resolved_name, then generic
    cmd = get_compile_cmd(app_root or "", resolved_name)
    if cmd:
        return cmd

    return (
        'bash -lc "'
        'afl-clang -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer '
        '-o {binary} {src} '
        '-I. -L. -lm -lpthread"'
    )
