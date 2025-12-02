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
        'afl-clang-fast -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer '
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
        'afl-clang-fast -g -O0 -fno-omit-frame-pointer -fsanitize=address,undefined '
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
        'afl-clang-fast -g -O0 -fno-omit-frame-pointer -fsanitize=address,undefined '
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
        'bash -lc "AFL_USE_ASAN=1 CXX=afl-clang-fast++ '
        'afl-clang-fast++ -std=c++20 -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer -fuse-ld=lld '
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
        'afl-clang-fast -std=c11 -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer '
        '-I. '
        '-o {binary} {src} '
        'cJSON.c cJSON_Utils.c"'
    ),
}


def get_compile_cmd(app_root: str, app_name: str) -> str | None:
    return APP_RULES.get(app_name)


def generate_compile_cmd_template(app_root: str | None = None, app_name: str | None = None) -> str:
    # If we have a per-app rule, use it
    if app_name:
        cmd = get_compile_cmd(app_root or "", app_name)
        if cmd:
            return cmd
    # Fallback generic: tune includes/libs as needed for your environment
    return (
        'bash -lc "'
        'afl-clang-fast -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer '
        '-o {binary} {src} '
        '-I. -L. -lm -lpthread"'
    )
