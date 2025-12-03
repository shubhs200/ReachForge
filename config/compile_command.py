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
    # analyze-image (static libs via vcpkg_installed/x64-linux-cromulence)
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
    "challenge": (
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
    # lamartine (header-only external includes via vcpkg_installed if present)
    "lamartine": (
        'bash -lc "AFL_USE_ASAN=1 CXX=afl-clang++ '
        'afl-clang++ -std=c++20 -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer -fuse-ld=lld '
        '-DASIO_NO_DEPRECATED -DASIO_STANDALONE -DHELLO_THERE '
        '-I. -Isrc '
        '-I build/vcpkg_installed/x64-linux-cromulence/include '
        '-I build/vcpkg_installed/x64-linux-cromulence/include/libxml2 '
        '-o {binary} {src} '
        'src/assert.cpp src/base64.cpp src/error_processor.cpp src/session.cpp src/share_finder.cpp '
        'src/util_env.cpp src/util_rand.cpp src/var_finder.cpp src/watcher.cpp '
        'src/doom/map.cpp src/doom/pwad.cpp src/doom/svg_writer.cpp src/doom/udmf_parser.cpp '
        'src/tpl/base.cpp src/tpl/index.cpp src/tpl/map.cpp src/tpl/upload.cpp '
        'build/vcpkg_installed/x64-linux-cromulence/lib/libsodium.a '
        'build/vcpkg_installed/x64-linux-cromulence/lib/libxml2.a '
        'build/vcpkg_installed/x64-linux-cromulence/lib/libz.a '
        '-ldl -lm"'
    ),
    "cjson": (
        'bash -lc "AFL_USE_ASAN=1 '
        'afl-clang -std=c11 -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer '
        '-I. '
        '-o {binary} {src} '
        'cJSON.c cJSON_Utils.c"'
    ),
}


def get_compile_cmd(app_root: str, app_name: str) -> str | None:
    return APP_RULES.get(app_name)


def generate_compile_cmd_template(app_root: str | None = None, app_name: str | None = None) -> str:
    """Return a compile command template.
    For analyze-image/challenge, auto-detect the vcpkg triplet (ellf vs cromulence)
    by probing the filesystem under <app_root>/build/vcpkg_installed/.
    """
    from pathlib import Path as _P

    ar = _P(app_root).resolve() if app_root else _P('.')

    def _pick_triplet(root: _P) -> str:
        candidates = [
            "x64-linux-ellf",
            "x64-linux-cromulence",
        ]
        base = root / "build" / "vcpkg_installed"
        for t in candidates:
            if (base / t / "include").exists():
                return t
        # Fallback to ellf if nothing found
        return "x64-linux-ellf"

    # Dynamic handling for our known apps
    if app_name in {"analyze-image", "challenge"}:
        trip = _pick_triplet(ar)
        inc = f"build/vcpkg_installed/{trip}/include"
        lib = f"build/vcpkg_installed/{trip}/lib"
        return (
            'bash -lc "AFL_USE_ASAN=1 '
            'afl-clang -g -O0 -fno-omit-frame-pointer -fsanitize=address,undefined '
            f'-I. -Iapp/src -I{inc} '
            '{src} '
            '-o {binary} '
            f'{lib}/libturbojpeg.a '
            f'{lib}/libtiff.a '
            f'{lib}/libopenjp2.a '
            f'{lib}/libjpeg.a '
            f'{lib}/libz.a '
            f'{lib}/libmicrohttpd.a '
            f'{lib}/libpng16.a '
            f'{lib}/liblzma.a '
            f'{lib}/libgif.a '
            '-lm -ldl -lpthread"'
        )

    if app_name == "lamartine":
        trip = _pick_triplet(ar)
        inc = f"build/vcpkg_installed/{trip}/include"
        inc_xml = f"build/vcpkg_installed/{trip}/include/libxml2"
        lib = f"build/vcpkg_installed/{trip}/lib"
        # C++ target with many project sources; {src} is the generated harness
        return (
            'bash -lc "AFL_USE_ASAN=1 CXX=afl-clang++ '
            'afl-clang++ -std=c++20 -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer -fuse-ld=lld '
            '-DASIO_NO_DEPRECATED -DASIO_STANDALONE -DHELLO_THERE '
            '-I. -Isrc '
            f'-I {inc} -I {inc_xml} '
            '-o {binary} {src} '
            'src/assert.cpp src/base64.cpp src/error_processor.cpp src/session.cpp src/share_finder.cpp '
            'src/util_env.cpp src/util_rand.cpp src/var_finder.cpp src/watcher.cpp '
            'src/doom/map.cpp src/doom/pwad.cpp src/doom/svg_writer.cpp src/doom/udmf_parser.cpp '
            'src/tpl/base.cpp src/tpl/index.cpp src/tpl/map.cpp src/tpl/upload.cpp '
            f'{lib}/libsodium.a '
            f'{lib}/libxml2.a '
            f'{lib}/libz.a '
            '-ldl -lm"'
        )

    # If we have a per-app static rule, use it
    if app_name:
        cmd = get_compile_cmd(app_root or "", app_name)
        if cmd:
            return cmd

    # Fallback generic: tune includes/libs as needed for your environment
    return (
        'bash -lc "'
        'afl-clang -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer '
        '-o {binary} {src} '
        '-I. -L. -lm -lpthread"'
    )
