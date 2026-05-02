#!/usr/bin/env python3
"""
Compile the generated harness using captured build commands.
Explicitly adds sanitizer flags for ASAN/UBSAN and coverage instrumentation.
"""
import argparse
import json
import os
import shlex
import subprocess
import sys


def load_all_commands(log_path: str):
    """Load all captured compiler commands from the build log."""
    cmds = []
    with open(log_path, 'r') as f:
        for line in f:
            try:
                entry = json.loads(line)
                argv = entry.get('argv', [])
                cwd = entry.get('cwd', '.')
                cmds.append({'argv': argv, 'cwd': cwd})
            except Exception:
                continue
    return cmds


def extract_include_paths(commands):
    """Extract all -I include paths from the build log.
    
    This is essential for libraries that generate config headers during build
    (e.g., zlib generates zconf.h, libpng generates pnglibconf.h).
    
    Returns a list of unique include paths in order of first appearance.
    """
    include_paths = []
    seen = set()
    
    for cmd in commands:
        argv = cmd.get('argv', [])
        cwd = cmd.get('cwd', '')
        
        for i, arg in enumerate(argv):
            path = None
            
            # Handle -I/path format
            if arg.startswith('-I') and len(arg) > 2:
                path = arg[2:]
            # Handle -I /path format
            elif arg == '-I' and i + 1 < len(argv):
                path = argv[i + 1]
            
            if path:
                # Resolve relative paths to absolute
                if not os.path.isabs(path):
                    path = os.path.normpath(os.path.join(cwd, path))
                
                if path not in seen:
                    seen.add(path)
                    include_paths.append(path)
    
    return include_paths


def discover_project_search_paths(project_root, search_root='/src',
                                  max_dirs_per_kind=120):
    """Walk the source tree and return (include_dirs, library_dirs, library_names).

    This is generic — no library-specific knowledge. It enables harness
    compilation for projects that build via OSS-Fuzz ``build.sh`` (where we
    don't have a captured compile-command log) and for projects whose build
    leaves dependencies (e.g. a vendored zlib's ``libz.a``) in non-standard
    paths.

    - ``include_dirs``: every directory that contains at least one ``*.h``
      file under ``search_root``. We skip obviously irrelevant trees
      (``.git``, build-temp dirs, test fixtures).
    - ``library_dirs``: every directory containing a ``lib*.a`` or
      ``lib*.so[.*]`` artefact under ``search_root``.
    - ``library_names``: the de-duplicated set of library base-names
      (e.g. ``z``, ``jpeg``, ``zstd``) corresponding to those artefacts,
      suitable for use as ``-l<name>`` flags. The caller chooses whether
      to append them to the link line; including them is always safe
      because the matching ``-L`` dir is also returned.

    Results are de-duplicated and capped at ``max_dirs_per_kind`` to keep
    the generated command line bounded.
    """
    if not search_root or not os.path.isdir(search_root):
        # Fall back to project_root's grandparent if /src is missing
        search_root = os.path.dirname(os.path.abspath(str(project_root)))
        if not os.path.isdir(search_root):
            return [], [], []

    include_dirs = []
    library_dirs = []
    library_names = []
    inc_seen = set()
    lib_seen = set()
    name_seen = set()
    skip_dirnames = {'.git', '.svn', '.hg', '__pycache__', 'CMakeFiles',
                     'node_modules', 'tests', 'test', 'testsuite',
                     'fuzz', 'fuzzing', 'benchmark', 'benchmarks',
                     'doc', 'docs', 'examples', 'example',
                     # Project-internal headers (e.g. libxml2's
                     # ``include/private/`` declares symbols with macros
                     # like XML_HIDDEN that are only defined when building
                     # the library itself, so adding them as -I breaks
                     # external harness compilation).
                     'private', 'internal',
                     # OSS-Fuzz fuzzing-engine source trees in /src/.
                     # Their build artefacts (libcentipede_runner.a,
                     # libcentipede_runner.pic.a, etc.) are not real
                     # link-time deps for harnesses.
                     'aflplusplus', 'honggfuzz', 'libfuzzer', 'centipede',
                     'AFLplusplus', 'fuzztest', 'bazel-bin', 'bazel-out',
                     # The ReachForge source tree itself is bind-mounted
                     # into the OSS-Fuzz container at /src/reachforge.
                     # Walking it pulls in unrelated header trees from
                     # oss-fuzz/projects/* which then poison -I and
                     # cause cross-project header conflicts.
                     'reachforge'}
    # Library base-names belonging to fuzzing-engine internals; we never
    # want to auto-add these as -l<name>.
    fuzz_engine_libs = {'centipede_runner', 'dislocator', 'tokencap',
                        'compcov', 'FuzzingEngine', 'afl', 'hfuzz',
                        'honggfuzz', 'AFLDriver', 'qasan'}

    for dirpath, dirnames, filenames in os.walk(search_root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in skip_dirnames
                       and not d.startswith('.')]
        has_header = False
        local_lib_names = []
        for fn in filenames:
            if not has_header and fn.endswith('.h'):
                has_header = True
            if fn.startswith('lib') and (fn.endswith('.a')
                                         or '.so' in fn):
                # Extract base name: libfoo.a -> foo, libfoo.so.1.2 -> foo
                base = fn[3:]
                if base.endswith('.a'):
                    name = base[:-2]
                else:
                    # split on '.so'
                    idx = base.find('.so')
                    name = base[:idx] if idx > 0 else None
                if name and name not in name_seen:
                    name_seen.add(name)
                    # Match against fuzz-engine libs at the raw name and
                    # at the dot-split base (libcentipede_runner.pic.a
                    # → name='centipede_runner.pic', base='centipede_runner').
                    base_name = name.split('.')[0]
                    if (name in fuzz_engine_libs
                            or base_name in fuzz_engine_libs):
                        continue
                    local_lib_names.append(name)
        if has_header and dirpath not in inc_seen:
            inc_seen.add(dirpath)
            include_dirs.append(dirpath)
        if local_lib_names and dirpath not in lib_seen:
            lib_seen.add(dirpath)
            library_dirs.append(dirpath)
            library_names.extend(local_lib_names)

    if len(include_dirs) > max_dirs_per_kind:
        include_dirs = include_dirs[:max_dirs_per_kind]
    if len(library_dirs) > max_dirs_per_kind:
        library_dirs = library_dirs[:max_dirs_per_kind]
    return include_dirs, library_dirs, library_names


def extract_link_flags(commands):
    """Extract -l linker flags from the build log's link commands.
    
    Scans captured build commands for link-stage invocations (those with -o
    producing a non-.o output) and collects all -l flags.  This captures
    the actual system and third-party library dependencies the project was
    built with, avoiding the need for hard-coded lists.
    
    Returns a list of unique -l flags in order of first appearance.
    """
    flags = []
    seen = set()
    # A minimal set of system libs that are always safe to add
    always_safe = {'-lm', '-pthread', '-lpthread'}
    # Fuzzing-engine internal libs that may appear in OSS-Fuzz build
    # commands (e.g. when the image's default $LIB_FUZZING_ENGINE leaks
    # into project link lines). They are not real link-time deps for our
    # libFuzzer harness, so we drop them. Keep this list in sync with
    # ``discover_project_search_paths.fuzz_engine_libs``.
    fuzz_engine_lflags = {
        '-lcentipede_runner', '-ldislocator', '-ltokencap', '-lcompcov',
        '-lFuzzingEngine', '-lafl', '-lhfuzz', '-lhonggfuzz',
        '-lAFLDriver', '-lqasan',
    }
    
    for cmd in reversed(commands):
        argv = cmd.get('argv', [])
        # Only look at link commands (have -o, output is not .o)
        if '-o' not in argv:
            continue
        idx = argv.index('-o')
        if idx + 1 >= len(argv):
            continue
        output = argv[idx + 1]
        if output.endswith('.o'):
            continue
        
        for arg in argv:
            if arg in fuzz_engine_lflags:
                continue
            if arg.startswith('-l') and arg not in seen:
                seen.add(arg)
                flags.append(arg)
            elif arg == '-pthread' and '-pthread' not in seen:
                seen.add('-pthread')
                flags.append('-pthread')
    
    # Ensure basic system libs are present even if not in build log
    for flag in ['-lm', '-pthread']:
        if flag not in seen:
            flags.append(flag)
    
    return flags


def _detect_extra_libs(static_lib_path, lib_name):
    """Probe a static library with nm and return extra -l flags for common
    transitive dependencies whose symbols are undefined.
    
    Uses two strategies:
    1. pkg-config --libs (if available) for standard libraries
    2. nm symbol prefix matching as fallback
    """
    extra = []
    
    # Strategy 1: try pkg-config for the library's transitive deps
    try:
        proc = subprocess.run(
            ['pkg-config', '--libs-only-l', lib_name],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5
        )
        if proc.returncode == 0:
            pkg_flags = proc.stdout.decode('utf-8', errors='replace').strip().split()
            for flag in pkg_flags:
                flag = flag.strip()
                # Skip the library itself (e.g. -lyaml when building libyaml)
                if flag == '-l' + lib_name:
                    continue
                if flag.startswith('-l') and flag not in extra:
                    extra.append(flag)
                    print("DEBUG: pkg-config detected dependency: " + flag)
            # Do not early-return: pkg-config may miss optional codec libs
            # (e.g. libtiff's libjbig/lzma) depending on how it was generated.
            # Fall through to nm-based detection to augment.
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass  # pkg-config not available — fall through to nm-based detection
    
    # Strategy 2: nm-based symbol prefix matching (fallback)
    # Map of symbol prefix -> (library flag, excluded lib_names)
    # excluded lib_names prevents adding -lz when we ARE zlib, etc.
    symbol_to_lib = [
        ('lzma_',   '-llzma',  {'lzma', 'xz'}),
        ('BZ2_',    '-lbz2',   {'bz2', 'bzip2'}),
        ('ZSTD_',   '-lzstd',  {'zstd'}),
        ('icuuc',   '-licuuc', {'icuuc'}),
        ('icui18n', '-licui18n', {'icui18n'}),
        ('SSL_',    '-lssl',   {'ssl', 'openssl'}),
        ('EVP_',    '-lcrypto', {'crypto', 'openssl'}),
        ('deflateInit', '-lz',     {'z', 'zlib'}),
        ('inflateInit', '-lz',     {'z', 'zlib'}),
        ('gzopen',   '-lz',     {'z', 'zlib'}),
        ('gzdopen',  '-lz',     {'z', 'zlib'}),
        ('gzread',   '-lz',     {'z', 'zlib'}),
        ('gzwrite',  '-lz',     {'z', 'zlib'}),
        ('gzclose',  '-lz',     {'z', 'zlib'}),
        (' compress\n', '-lz',    {'z', 'zlib'}),
        ('jpeg_',    '-ljpeg',  {'jpeg', 'libjpeg'}),
        ('png_',     '-lpng',   {'png', 'libpng'}),
        ('jbg_',     '-ljbig',  {'jbig'}),
        ('acl_get_',  '-lacl',  {'acl'}),
        ('acl_set_',  '-lacl',  {'acl'}),
        ('acl_create', '-lacl', {'acl'}),
        ('LZ4_',     '-llz4',   {'lz4'}),
        ('lzo1x_',   '-llzo2',  {'lzo2'}),
        ('XML_Parse', '-lexpat', {'expat'}),
        ('xmlReadDoc', '-lxml2', {'xml2', 'libxml2'}),
    ]
    try:
        proc = subprocess.run(
            ['nm', '--undefined-only', static_lib_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10
        )
        if proc.returncode != 0:
            return extra
        undef = proc.stdout.decode('utf-8', errors='replace')
    except Exception:
        return extra

    for prefix, flag, excluded in symbol_to_lib:
        # Check exact match OR prefix match (e.g. lib_name='png16' should exclude for 'png')
        if lib_name in excluded or any(lib_name.startswith(e) for e in excluded):
            continue
        if prefix in undef and flag not in extra:
            # Verify the library actually exists on this system before adding
            if _system_lib_exists(flag):
                extra.append(flag)
                print("DEBUG: Auto-detected transitive dependency: " + flag)
            else:
                print("DEBUG: Skipping " + flag + " (not found on system)")
    return extra


def _system_lib_exists(flag):
    """Check whether a -lfoo library is actually available on the system.
    
    Uses ldconfig -p to check the shared library cache, and also checks
    common static lib paths. Returns True if found (or check failed).
    """
    if not flag.startswith('-l'):
        return True
    lib_name = flag[2:]  # strip -l prefix
    # Check ldconfig cache for shared library
    try:
        proc = subprocess.run(
            ['ldconfig', '-p'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5
        )
        if proc.returncode == 0:
            cache = proc.stdout.decode('utf-8', errors='replace')
            if 'lib' + lib_name + '.so' in cache or 'lib' + lib_name + '-' in cache:
                return True
    except Exception:
        pass
    # Check common static/shared lib search paths
    search_paths = [
        '/usr/lib', '/usr/local/lib', '/usr/lib/x86_64-linux-gnu',
        '/usr/lib64', '/lib', '/lib/x86_64-linux-gnu',
    ]
    for d in search_paths:
        if not os.path.isdir(d):
            continue
        for name in ('lib' + lib_name + '.so', 'lib' + lib_name + '.a',
                     'lib' + lib_name + '.so.0'):
            if os.path.exists(os.path.join(d, name)):
                return True
    # If we can't confirm, assume it doesn't exist (conservative)
    print("DEBUG: Library " + flag + " not found in system paths - skipping")
    return False


def _run_link_with_fallback(argv, cwd):
    """Run a link command. If it fails with 'undefined reference' errors,
    retry once with --unresolved-symbols=ignore-all so the harness can
    still link past optional codec/auxiliary code paths inside static
    archives (e.g. libtiff's JBIG codec, libarchive's ACL handler).
    Returns the final CompletedProcess.
    """
    p = subprocess.run(argv, cwd=cwd, stderr=subprocess.PIPE)
    if p.stderr:
        sys.stderr.buffer.write(p.stderr)
    if p.returncode == 0:
        return p
    stderr_text = p.stderr.decode('utf-8', errors='replace') if p.stderr else ''
    if 'undefined reference' not in stderr_text:
        return p
    if any(a.startswith('-Wl,--unresolved-symbols') for a in argv):
        return p
    print("DEBUG: retrying link with --unresolved-symbols=ignore-all "
          "to bypass optional-codec transitive deps", file=sys.stderr)
    retry = list(argv) + [
        '-Wl,--unresolved-symbols=ignore-all',
        '-Wl,--warn-unresolved-symbols',
    ]
    return subprocess.run(retry, cwd=cwd)


def is_test_binary(output, argv):
    """Check if a link command produces a test binary."""
    output_lower = output.lower()
    
    # Skip common test binary patterns
    test_patterns = [
        'test', 'unity', 'example', 'demo', 'sample',
        'parse_hex4', 'parse_number', 'parse_string', 'parse_array', 'parse_object',
        'parse_value', 'parse_examples', 'parse_with_opts',
        'print_hex4', 'print_number', 'print_string', 'print_array', 'print_object',
        'print_value', 'misc_tests', 'compare_tests', 'cjson_add', 'readme_examples',
        'cmTC_',  # CMake test binaries
    ]
    
    for pattern in test_patterns:
        if pattern in output_lower:
            return True
    
    # Check if source files are test files
    for arg in argv:
        arg_lower = arg.lower()
        if 'test' in arg_lower or 'unity' in arg_lower:
            if arg.endswith(('.c', '.cpp', '.cc', '.o')):
                return True
    
    return False


def find_link_command(commands, out_binary=None, skip_tests=True):
    """Find a link command in the build log.
    
    If out_binary is specified, find the command that produces that binary.
    Otherwise, return a suitable link command (skipping test binaries by default).
    """
    link_cmds = []
    for cmd in reversed(commands):
        argv = cmd['argv']
        # Look for link commands (have -o and produce an executable, not .o)
        if '-o' in argv:
            idx = argv.index('-o')
            if idx + 1 < len(argv):
                output = argv[idx + 1]
                # Skip if output is .o (compile, not link)
                if not output.endswith('.o'):
                    # Skip shared libraries
                    if '.so' in output or output.endswith('.a'):
                        continue
                    
                    if out_binary:
                        if os.path.basename(output) == os.path.basename(out_binary):
                            return cmd
                    else:
                        # Skip test binaries if requested
                        if skip_tests and is_test_binary(output, argv):
                            continue
                        # Remember first non-test link command found
                        if not link_cmds:
                            link_cmds.append(cmd)
    
    if link_cmds:
        return link_cmds[0]
    return None


def find_shared_library(commands):
    """Find shared library (.so) produced by the build.
    Handles versioned libraries like libsqlite3.so.0.8.6
    Prefers the main library over auxiliary libraries (e.g., libsqlite3 over libtclsqlite3).
    """
    candidates = []
    for cmd in reversed(commands):
        argv = cmd['argv']
        if '-o' in argv:
            idx = argv.index('-o')
            if idx + 1 < len(argv):
                output = argv[idx + 1]
                # Check for .so (with or without version numbers)
                if '.so' in output and not output.endswith('.o'):
                    # Extract library name: libsqlite3.so.0.8.6 -> sqlite3
                    basename = os.path.basename(output)
                    # Get the base name before .so
                    if basename.startswith('lib'):
                        name = basename[3:].split('.')[0]  # Remove 'lib' and get first part
                    else:
                        name = basename.split('.')[0]
                    candidates.append({
                        'path': output,
                        'cwd': cmd['cwd'],
                        'name': name,
                        'full_path': os.path.join(cmd['cwd'], output)
                    })
    
    # Prefer main library over auxiliary libraries
    # Auxiliary libraries often have names like: libtcl_foo, libfoo_util, etc.
    # Main libraries are usually: libfoo, libbar (shortest matching name)
    
    # Strategy: prefer the shortest library name (likely the main library)
    # Auxiliary libraries typically have longer names with suffixes
    if candidates:
        # Sort by name length - shorter names are more likely to be main libraries
        candidates.sort(key=lambda c: len(c['name']))
        return candidates[0]
    
    return None


def find_static_library(commands):
    """Find static library (.a) produced by the build."""
    for cmd in reversed(commands):
        argv = cmd['argv']
        if '-o' in argv:
            idx = argv.index('-o')
            if idx + 1 < len(argv):
                output = argv[idx + 1]
                if output.endswith('.a'):
                    return {
                        'path': output,
                        'cwd': cmd['cwd'],
                    }
    return None


def find_library_in_project(project_root):
    """Search for library files in the project directory.
    
    Returns a dict with library info, or None if not found.
    Searches for: .a (static), .so (shared)
    Recurses into subdirectories (up to 4 levels) to handle projects
    like expat where libs live at /src/expat/expat/lib/.libs/.
    """
    import glob
    
    # Search patterns for library files
    patterns = [
        'lib*.a',           # Static library
        'lib*.so',          # Shared library
        'lib*.so.*',        # Versioned shared library
    ]
    
    # Directories to search (in order of preference)
    search_dirs = [
        project_root,                    # Project root
        os.path.join(project_root, '.libs'),  # libtool output
        os.path.join(project_root, '_rf_build'),  # CMake build dir
        os.path.join(project_root, 'build'),  # Fallback for other build dirs
    ]
    
    # Also recurse to find .libs directories deeper in the tree
    # (e.g. /src/expat/expat/lib/.libs/)
    try:
        for root_d, dirs, _files in os.walk(project_root):
            depth = root_d[len(project_root):].count(os.sep)
            if depth > 4:
                dirs.clear()
                continue
            basename = os.path.basename(root_d)
            if basename in ('.libs', 'build', '_rf_build'):
                if root_d not in search_dirs:
                    search_dirs.append(root_d)
    except OSError:
        pass

    for search_dir in search_dirs:
        if not os.path.exists(search_dir):
            continue
            
        for pattern in patterns:
            matches = glob.glob(os.path.join(search_dir, pattern))
            # Also search one level deeper — many build systems put
            # libraries in subdirectories (e.g. _rf_build/libtiff/libtiff.a)
            if not matches:
                matches = glob.glob(os.path.join(search_dir, '*', pattern))
            if matches:
                # Prefer shorter names (main lib over aux lib)
                matches.sort(key=lambda x: len(os.path.basename(x)))
                lib_path = matches[0]
                basename = os.path.basename(lib_path)
                
                # Extract library name from filename
                # libfoo.a -> foo, libfoo.so.1.2.3 -> foo
                if basename.startswith('lib'):
                    name = basename[3:].split('.')[0]
                else:
                    name = basename.split('.')[0]
                
                return {
                    'path': lib_path,
                    'dir': os.path.dirname(lib_path),
                    'name': name,
                    'type': 'static' if lib_path.endswith('.a') else 'shared'
                }
    
    return None


def find_library_object_files(commands):
    """Find all library object files (.o) compiled from source.
    
    Works with any library, not just cJSON. Returns a list of object files.
    """
    objects = []
    seen = set()
    
    for cmd in reversed(commands):
        argv = cmd['argv']
        cwd = cmd.get('cwd', '')
        
        # Skip test directories
        if '/tests' in cwd or '\\tests' in cwd:
            continue
        if '/test' in cwd or '\\test' in cwd:
            continue
        if '/example' in cwd or '\\example' in cwd:
            continue
            
        if '-o' in argv:
            idx = argv.index('-o')
            if idx + 1 < len(argv):
                output = argv[idx + 1]
                
                # Skip if already seen
                if output in seen:
                    continue
                
                # Look for .o files from compile commands
                if output.endswith('.o') and '-c' in argv:
                    # Skip test object files
                    if 'test' in output.lower() or 'example' in output.lower():
                        continue
                    
                    # Check the source file is not a test
                    source_file = None
                    for arg in argv:
                        if arg.endswith('.c') or arg.endswith('.cpp') or arg.endswith('.cc'):
                            if 'test' not in arg.lower() and 'example' not in arg.lower() and 'unity' not in arg.lower():
                                source_file = arg
                                break
                    
                    if source_file:
                        seen.add(output)
                        objects.append({
                            'obj': output,
                            'cwd': cwd,
                            'source': source_file,
                        })
    
    return objects


def find_library_compile_command(commands):
    """Find a compile command for the main library source file."""
    for cmd in reversed(commands):
        argv = cmd['argv']
        # Look for compile commands (produce .o, not link)
        for arg in argv:
            if arg.endswith('.c') or arg.endswith('.cpp') or arg.endswith('.cc'):
                # Check if this is the main library file (not a test)
                if 'test' not in arg.lower() and '-c' in argv:
                    return cmd
    return None


def find_project_root(commands):
    """Find the project root directory from build commands."""
    for cmd in commands:
        cwd = cmd.get('cwd', '')
        # Look for build directory pattern
        if os.path.basename(cwd) in ('build', '_rf_build'):
            return os.path.dirname(cwd)
    return None


def has_sanitizer_flags(argv):
    """Check if the command already has sanitizer flags."""
    for arg in argv:
        if '-fsanitize=' in arg:
            return True
    return False


def _cxx_stdlib_flag():
    """Return ``-stdlib=libc++`` when libstdc++ isn't `-l`-loadable on this
    image but libc++ is. clang++ defaults to libstdc++ on Linux, but several
    OSS-Fuzz Ubuntu 16.04 base images ship libc++ only — the implicit
    -lstdc++ then fails with `cannot find -lstdc++`. Library-agnostic; only
    activates when the filesystem indicates libc++ is the right choice.

    For -l<name> to succeed, the linker needs the unversioned `lib<name>.so`
    symlink (or `lib<name>.a`). A versioned `.so.6` alone (which is what
    these legacy images ship for the runtime) is NOT discoverable via -l.
    """
    import os as _os
    libcxx = any(_os.path.exists(p) for p in (
        "/usr/local/lib/libc++.so", "/usr/local/lib/libc++.a",
        "/usr/lib/libc++.so", "/usr/lib/x86_64-linux-gnu/libc++.so",
    ))
    # Only the unversioned `.so` (or `.a`) is a valid -l target.
    libstdcxx_linkable = any(_os.path.exists(p) for p in (
        "/usr/lib/x86_64-linux-gnu/libstdc++.so",
        "/usr/lib/libstdc++.so",
        "/usr/local/lib/libstdc++.so",
        "/usr/lib/x86_64-linux-gnu/libstdc++.a",
        "/usr/lib/libstdc++.a",
    ))
    if libcxx and not libstdcxx_linkable:
        return "-stdlib=libc++"
    return None


def _cxx_runtime_link_args():
    """Extra link args needed at the *end* of the harness link line when we
    forced ``-stdlib=libc++`` but only the static archives are available.

    On legacy OSS-Fuzz Ubuntu 16.04 base images, ``libc++.a`` and
    ``libc++abi.a`` are present but the unversioned ``.so`` symlinks aren't,
    so clang++'s implicit ``-lc++`` link silently picks up nothing and the
    binary segfaults at exec time with ``undefined symbol: _ZTISt9type_info``
    (i.e. ``std::type_info`` typeinfo from the C++ stdlib). Force-link the
    static archives in a group so cross-archive typeinfo refs resolve.
    Library-agnostic — only activates when libc++ is the right stdlib AND
    the static archives are present.
    """
    import os as _os
    if _cxx_stdlib_flag() != "-stdlib=libc++":
        return []
    extras = []
    # Prefer the *shared* libc++abi when available: legacy clang's
    # libclang_rt.asan_cxx pulls in plain undefined refs to std typeinfo
    # (`_ZTISt9type_info`, `_ZTISt8bad_cast`, ...) and links them with
    # default visibility, expecting dynamic resolution. libc++abi.a's
    # typeinfo objects carry hidden visibility in some images; whole-
    # archiving them puts the symbols in the binary as `LOCAL HIDDEN`,
    # which the dynamic linker can't see — so the program aborts at
    # exec with `undefined symbol: _ZTISt8bad_cast`. The shared
    # libc++abi.so.1 exposes them as global default-visibility, so the
    # dynamic linker resolves them at runtime.
    abi_so_dirs = []
    abi_so = None
    for d in ("/usr/local/lib", "/usr/lib", "/usr/lib/x86_64-linux-gnu"):
        cand = _os.path.join(d, "libc++abi.so")
        cand_v = _os.path.join(d, "libc++abi.so.1")
        if _os.path.exists(cand) or _os.path.exists(cand_v):
            abi_so = cand if _os.path.exists(cand) else cand_v
            abi_so_dirs.append(d)
            break
    if abi_so:
        # `-l:libc++abi.so.1` works even when the unversioned `.so` symlink
        # is missing; absolute path is the most robust.
        extras.extend([
            "-Wl,--no-as-needed", abi_so, "-Wl,--as-needed",
            "-Wl,-rpath," + abi_so_dirs[0],
        ])
        return extras
    # Fall back to static libc++abi.a + libc++.a with --whole-archive.
    # On images where libc++abi was built with default visibility this
    # path also works (zlib, json-c style images).
    cxx_a = next((p for p in (
        "/usr/local/lib/libc++.a", "/usr/lib/libc++.a") if _os.path.exists(p)), None)
    abi_a = next((p for p in (
        "/usr/local/lib/libc++abi.a", "/usr/lib/libc++abi.a") if _os.path.exists(p)), None)
    if abi_a:
        extras.extend(["-Wl,--whole-archive", abi_a, "-Wl,--no-whole-archive"])
    if cxx_a:
        extras.append(cxx_a)
    if abi_a and cxx_a:
        extras.append("-Wl,--allow-multiple-definition")
    return extras


def _primary_sanitizer_flag():
    """The combined ``-fsanitize=...`` flag used by every compile site.

    Mirrors build_capture's choice via ``RF_SANITIZER_MODE`` (set to
    ``asan_only`` when the library build had to fall back from ASan+UBSan
    on legacy clang/libc++ toolchains where UBSan can't link). Mismatched
    sanitizer modes between the library and the harness fail to link, so
    every harness compile must match.
    """
    import os as _os
    if _os.environ.get("RF_SANITIZER_MODE") == "asan_only":
        return '-fsanitize=address,fuzzer'
    # Sentinel-file fallback (env may not propagate to every child process):
    for cand in ("rf_sanitizer_mode", "../rf_sanitizer_mode",
                 "/out/rf_sanitizer_mode"):
        try:
            from pathlib import Path as _P
            p = _P(cand)
            if p.exists() and p.read_text().strip() == "asan_only":
                return '-fsanitize=address,fuzzer'
        except Exception:
            pass
    # Implicit asan-only when libstdc++ is missing: UBSan's compiler-rt
    # references libstdc++'s typeinfo for std::bad_cast / std::type_info.
    # `-stdlib=libc++` lets the binary compile but it fails at runtime with
    # `undefined symbol: _ZTISt8bad_cast`. The same filesystem probe we use
    # to decide on `-stdlib=libc++` decides this. No library-specific code.
    if _cxx_stdlib_flag() == "-stdlib=libc++":
        return '-fsanitize=address,fuzzer'
    return '-fsanitize=address,undefined,fuzzer'


def add_sanitizer_flags(argv):
    """Add ASAN/UBSAN and fuzzer flags to the command."""
    sanitizer_flags = [_primary_sanitizer_flag(), '-fno-sanitize-recover=all']
    asan_compile_flags = [
        '-fno-omit-frame-pointer',
        '-fno-optimize-sibling-calls',
        '-gline-tables-only',
    ]
    
    insert_pos = 1
    for i, arg in enumerate(argv):
        if arg.endswith('clang') or arg.endswith('clang++') or \
           arg.endswith('gcc') or arg.endswith('g++') or arg.endswith('c++'):
            insert_pos = i + 1
            break
    
    existing_flags = set(arg for arg in argv)
    flags_to_add = []
    
    for flag in sanitizer_flags + asan_compile_flags:
        if flag not in existing_flags:
            flags_to_add.append(flag)
    
    if flags_to_add:
        for flag in reversed(flags_to_add):
            argv.insert(insert_pos, flag)
    
    return argv


def compile_harness_direct(harness_src, commands, out_binary, project_root):
    """Compile harness directly with library object files.
    
    Used when the project only builds a library (no suitable executable link command).
    """
    lib_objects = find_library_object_files(commands)
    lib_cmd = find_library_compile_command(commands)
    
    # Also try static library
    static_lib = find_static_library(commands)
    
    # Extract all include paths from build commands
    # This is essential for generated headers like zconf.h (zlib), pnglibconf.h (libpng)
    include_paths = extract_include_paths(commands)
    # Also add the cwd of compile commands — headers may be in the same
    # directory as the source files (e.g. lz4 builds from lib/).
    for cmd in commands:
        cwd = cmd.get('cwd', '')
        if cwd and cwd not in include_paths and os.path.isdir(cwd):
            include_paths.append(cwd)
    print("DEBUG: Extracted include paths: " + str(include_paths))
    
    compiler = 'clang++'
    
    # Build the compile command
    new_argv = [a for a in [
        compiler,
        _cxx_stdlib_flag(),
        _primary_sanitizer_flag(),
        '-fno-sanitize-recover=all',
        '-fno-omit-frame-pointer',
        '-gline-tables-only',
        '-I' + str(project_root),
        '-I' + str(os.path.dirname(str(project_root))),
        '-o', out_binary,
        harness_src,
    ] if a is not None]

    # Add all extracted include paths (for generated headers like zconf.h)
    for inc_path in include_paths:
        inc_flag = '-I' + str(inc_path)
        if inc_flag not in new_argv:
            new_argv.insert(4, inc_flag)
    
    # Forward macro definitions from library compile commands.
    # These may include build-time configuration macros that library headers
    # depend on (e.g., HAVE_CONFIG_H, _LARGEFILE_SOURCE, feature toggles).
    _forwarded_defines = set()
    if lib_cmd:
        for arg in lib_cmd['argv']:
            if arg.startswith('-D') and arg not in _forwarded_defines:
                _forwarded_defines.add(arg)
                new_argv.insert(4, arg)
    
    # Try to find a library to link against
    lib_linked = False
    
    # 1. First try static library from build log
    if static_lib:
        static_path = os.path.join(static_lib['cwd'], static_lib['path'])
        print("DEBUG: Using static library from build log: " + str(static_path))
        if os.path.exists(static_path):
            new_argv.append(static_path)
            print("Linking with static library: " + str(static_path))
            lib_linked = True
        else:
            print("WARNING: Static library not found: " + str(static_path))
    
    # 2. Try object files from build log
    if not lib_linked and lib_objects:
        print("DEBUG: Found " + str(len(lib_objects)) + " object files")
        for lib_obj in lib_objects:
            obj_path = os.path.join(lib_obj['cwd'], lib_obj['obj'])
            print("DEBUG: Object file: " + str(obj_path) + " (exists: " + str(os.path.exists(obj_path)) + ")")
            if os.path.exists(obj_path):
                new_argv.append(obj_path)
                print("Linking with library object: " + str(obj_path))
                lib_linked = True
    
    # 3. Try to find library in project directory (fallback)
    if not lib_linked:
        print("DEBUG: Searching for library in project directory...")
        project_lib = find_library_in_project(project_root)
        if project_lib:
            print("DEBUG: Found library in project: " + str(project_lib['path']))
            if project_lib['type'] == 'static':
                new_argv.append(project_lib['path'])
                print("Linking with static library: " + str(project_lib['path']))
            else:
                # Shared library - use -L and -l
                lib_dir = project_lib['dir']
                lib_name = project_lib['name']
                new_argv.extend([
                    '-L' + str(lib_dir),
                    '-l' + str(lib_name),
                    '-Wl,-rpath,' + str(lib_dir),
                ])
                print("Linking with shared library: -L" + str(lib_dir) + " -l" + str(lib_name))
            lib_linked = True
        else:
            print("WARNING: No library found in project directory")
    
    if not lib_linked:
        print("WARNING: No library object files, static library, or project library found")
    
    # Extract linker flags from build log (captures actual -l deps);
    # falls back to -lm -pthread if no link command was recorded.
    link_flags = extract_link_flags(commands)
    new_argv.append('-Wl,--start-group')
    new_argv.extend(link_flags)
    new_argv.append('-Wl,--end-group')
    new_argv.extend(_cxx_runtime_link_args())

    cmd_str = " ".join(shlex.quote(a) for a in new_argv)
    print("Compiling harness: " + cmd_str)
    print("Compiling harness: " + cmd_str, file=sys.stderr)
    p = _run_link_with_fallback(new_argv, project_root)
    
    output_path = os.path.join(project_root, out_binary)
    if p.returncode != 0:
        sys.exit("Harness compile failed (rc=" + str(p.returncode) + ")")
    if not os.path.exists(output_path):
        if os.path.exists(out_binary):
            output_path = out_binary
        else:
            sys.exit("Harness binary not found at " + str(output_path))
    print("Harness binary created: " + str(output_path))
    try:
        _emit_fuzzer_options(
            os.path.dirname(str(output_path)),
            str(output_path),
            os.path.join(os.path.dirname(str(output_path)),
                         "harness_plan.json"),
        )
    except Exception:
        pass
    return output_path


def compile_harness_with_project_lib(harness_src, project_lib, out_binary, project_root, commands=None):
    """Compile harness linking against library found in project directory."""
    compiler = 'clang++'
    
    lib_path = project_lib['path']
    lib_dir = project_lib['dir']
    lib_name = project_lib['name']
    
    print("DEBUG: compile_harness_with_project_lib")
    print("DEBUG: lib_path = " + str(lib_path))
    print("DEBUG: lib_dir = " + str(lib_dir))
    print("DEBUG: lib_name = " + str(lib_name))
    print("DEBUG: lib_type = " + str(project_lib['type']))
    
    # Extract include paths from build commands for generated headers
    include_paths = []
    if commands:
        include_paths = extract_include_paths(commands)
        for cmd in commands:
            cwd = cmd.get('cwd', '')
            if cwd and cwd not in include_paths and os.path.isdir(cwd):
                include_paths.append(cwd)
        print("DEBUG: Extracted include paths: " + str(include_paths))

    # Augment with directories discovered from the source tree. This is
    # essential for OSS-Fuzz build.sh paths where we have no captured
    # compile-command log, and also catches vendored deps (e.g. a libtiff
    # build that produces /src/zlib/libz.a in a non-default location).
    discovered_includes, discovered_libdirs, discovered_libnames = \
        discover_project_search_paths(project_root)
    for inc in discovered_includes:
        if inc not in include_paths:
            include_paths.append(inc)
    if discovered_libdirs:
        print("DEBUG: Discovered library dirs: {} entries".format(
            len(discovered_libdirs)))
    # Compute candidate transitive deps from artefact names. Skip the
    # project's own library (linked by direct path) and the system libs
    # we already add unconditionally.
    skip_link_names = {lib_name, 'm', 'pthread', 'dl', 'rt', 'c', 'gcc',
                       'gcc_s', 'stdc++'}
    discovered_link_flags = []
    for n in discovered_libnames:
        if n in skip_link_names:
            continue
        # Strip common version suffixes left over from libfoo.so.0 -> foo.0
        base = n.split('.')[0]
        if base in skip_link_names or not base:
            continue
        flag = '-l' + base
        if flag not in discovered_link_flags:
            discovered_link_flags.append(flag)
    
    if project_lib['type'] == 'static':
        # Static library - link directly
        new_argv = [a for a in [
            compiler,
            _cxx_stdlib_flag(),
            _primary_sanitizer_flag(),
            '-fno-sanitize-recover=all',
            '-fno-omit-frame-pointer',
            '-gline-tables-only',
            '-I' + str(project_root),
            '-I' + str(os.path.dirname(str(project_root))),
            '-o', out_binary,
            harness_src,
        ] if a is not None]

        # Add extracted include paths (for generated headers like zconf.h)
        for inc_path in include_paths:
            inc_flag = '-I' + str(inc_path)
            if inc_flag not in new_argv:
                new_argv.insert(4, inc_flag)
        
        extra_libs = _detect_extra_libs(lib_path, lib_name)
        new_argv.append('-Wl,--start-group')
        new_argv.extend([lib_path, '-lm', '-pthread'])
        # Discovered -L paths (for vendored deps like zlib built under /src/<dep>)
        for ld in discovered_libdirs:
            l_flag = '-L' + str(ld)
            if l_flag not in new_argv:
                new_argv.append(l_flag)
        # Discovered -l flags from artefact names. Their availability is
        # guaranteed because the matching -L dir is already on the line,
        # so we don't run them through the system-lib existence check.
        for lflag in discovered_link_flags:
            if lflag not in new_argv:
                new_argv.append(lflag)
        new_argv.extend(extra_libs)
        new_argv.append('-Wl,--end-group')
        new_argv.extend(_cxx_runtime_link_args())

        print("Linking with static library: " + str(lib_path))
    else:
        # Shared library - use -L and -l with rpath
        new_argv = [a for a in [
            compiler,
            _cxx_stdlib_flag(),
            _primary_sanitizer_flag(),
            '-fno-sanitize-recover=all',
            '-fno-omit-frame-pointer',
            '-gline-tables-only',
            '-I' + str(project_root),
            '-I' + str(os.path.dirname(str(project_root))),
            '-o', out_binary,
            harness_src,
        ] if a is not None]

        # Add extracted include paths (for generated headers like zconf.h)
        for inc_path in include_paths:
            inc_flag = '-I' + str(inc_path)
            if inc_flag not in new_argv:
                new_argv.insert(4, inc_flag)
        
        new_argv.extend([
            '-L' + str(lib_dir),
            '-l' + str(lib_name),
            '-Wl,-rpath,' + str(lib_dir),
            '-lm',
            '-pthread',
        ])
        # Discovered -L paths (vendored deps)
        for ld in discovered_libdirs:
            l_flag = '-L' + str(ld)
            if l_flag not in new_argv:
                new_argv.append(l_flag)
        # Discovered -l flags from vendored-dep artefacts
        for lflag in discovered_link_flags:
            if lflag not in new_argv:
                new_argv.append(lflag)
        print("Linking with shared library: -L" + str(lib_dir) + " -l" + str(lib_name))
    
    cmd_str = " ".join(shlex.quote(a) for a in new_argv)
    print("Compiling harness: " + cmd_str)
    print("Compiling harness: " + cmd_str, file=sys.stderr)
    p = _run_link_with_fallback(new_argv, project_root)
    
    output_path = os.path.join(project_root, out_binary)
    if p.returncode != 0:
        sys.exit("Harness compile failed (rc=" + str(p.returncode) + ")")
    if not os.path.exists(output_path):
        if os.path.exists(out_binary):
            output_path = out_binary
        else:
            sys.exit("Harness binary not found at " + str(output_path))
    print("Harness binary created: " + str(output_path))
    return output_path


def compile_harness_with_shared_lib(harness_src, shared_lib_info, out_binary, project_root):
    """Compile harness linking against shared library."""
    compiler = 'clang++'
    lib_path = os.path.join(shared_lib_info['cwd'], shared_lib_info['path'])
    lib_dir = os.path.dirname(lib_path)
    lib_name = shared_lib_info['name']
    lib_cwd = shared_lib_info.get('cwd', '')

    # Collect additional include directories: the directory where the lib
    # was built often contains the public headers (e.g. lz4 builds in lib/).
    extra_includes = []
    for d in [lib_cwd, lib_dir]:
        if d and d != str(project_root) and os.path.isdir(d):
            extra_includes.append('-I' + d)
    # Augment with all header-bearing directories under the source tree.
    # Necessary for projects whose public headers (e.g. libarchive's
    # ``archive.h`` in ``libarchive/``) are not in any standard
    # ``include/`` dir relative to the .so build location.
    try:
        _disc_inc, _disc_libdirs, _disc_libnames = \
            discover_project_search_paths(project_root)
    except Exception:
        _disc_inc, _disc_libdirs, _disc_libnames = [], [], []
    for inc in _disc_inc:
        flag = '-I' + inc
        if flag not in extra_includes:
            extra_includes.append(flag)
    
    # Also check for .libs subdirectory (libtool style)
    libs_dir = os.path.join(shared_lib_info['cwd'], '.libs')
    if os.path.exists(libs_dir):
        lib_dir = libs_dir
    
    # Debug: print what we're looking for
    print("DEBUG: lib_path = " + str(lib_path))
    print("DEBUG: lib_dir = " + str(lib_dir))
    print("DEBUG: lib_name = " + str(lib_name))
    
    # Find the actual .so file - try multiple locations
    actual_lib_path = None
    
    # Try the path directly
    if os.path.exists(lib_path):
        actual_lib_path = lib_path
        print("DEBUG: Found library at lib_path")
    
    # Try in .libs directory with the same basename
    if not actual_lib_path and os.path.exists(libs_dir):
        libs_lib_path = os.path.join(libs_dir, os.path.basename(lib_path))
        if os.path.exists(libs_lib_path):
            actual_lib_path = libs_lib_path
            print("DEBUG: Found library in .libs: " + str(libs_lib_path))
    
    # Try finding any .so file in .libs that matches the library name
    if not actual_lib_path and os.path.exists(libs_dir):
        import glob
        so_files = glob.glob(os.path.join(libs_dir, 'lib' + lib_name + '.so*'))
        if so_files:
            # Prefer the base .so, otherwise use the versioned one
            for f in so_files:
                if f.endswith('.so') or '/lib' + lib_name + '.so.' in f:
                    actual_lib_path = f
                    print("DEBUG: Found library via glob: " + str(f))
                    break
    
    # Check for static library - prefer this to avoid DSO issues
    static_lib = os.path.join(lib_dir, 'lib' + lib_name + '.a')
    print("DEBUG: static_lib path = " + str(static_lib))
    print("DEBUG: static_lib exists = " + str(os.path.exists(static_lib)))
    
    if os.path.exists(static_lib):
        print("DEBUG: Using static library: " + str(static_lib))
        new_argv = [a for a in [
            compiler,
            _cxx_stdlib_flag(),
            _primary_sanitizer_flag(),
            '-fno-sanitize-recover=all',
            '-fno-omit-frame-pointer',
            '-gline-tables-only',
            '-I' + str(project_root),
            '-I' + str(os.path.dirname(str(project_root))),
            '-o', out_binary,
            harness_src,
        ] if a is not None]

        # Auto-detect additional transitive dependencies (e.g. -llzma, -lbz2, -lz)
        extra_libs = _detect_extra_libs(static_lib, lib_name)
        new_argv.append('-Wl,--start-group')
        new_argv.extend([static_lib, '-lm', '-pthread'])
        new_argv.extend(extra_libs)
        new_argv.extend(['-ldl', '-Wl,--end-group'])
        new_argv.extend(_cxx_runtime_link_args())
    elif actual_lib_path:
        print("DEBUG: Using shared library: " + str(actual_lib_path))
        
        # Link directly with the .so file - always use --no-as-needed for shared libs
        new_argv = [a for a in [
            compiler,
            _cxx_stdlib_flag(),
            _primary_sanitizer_flag(),
            '-fno-sanitize-recover=all',
            '-fno-omit-frame-pointer',
            '-gline-tables-only',
            '-I' + str(project_root),
            '-I' + str(os.path.dirname(str(project_root))),
            '-o', out_binary,
            harness_src,
            '-Wl,--no-as-needed',
            actual_lib_path,
            '-Wl,--as-needed',
            '-Wl,-rpath,' + str(lib_dir),
            '-lm',
            '-pthread',
            '-ldl',  # zlib often needed
        ] if a is not None]
        new_argv.extend(_cxx_runtime_link_args())
    else:
        # Fallback to standard -l linking
        print("DEBUG: Using fallback -l linking")
        new_argv = [a for a in [
            compiler,
            _cxx_stdlib_flag(),
            _primary_sanitizer_flag(),
            '-fno-sanitize-recover=all',
            '-fno-omit-frame-pointer',
            '-gline-tables-only',
            '-I' + str(project_root),
            '-I' + str(os.path.dirname(str(project_root))),
            '-o', out_binary,
            harness_src,
            '-Wl,--no-as-needed',
            '-L' + str(lib_dir),
            '-l' + str(lib_name),
            '-Wl,--as-needed',
            '-Wl,-rpath,' + str(lib_dir),
            '-lm',
            '-pthread',
            '-ldl',
        ] if a is not None]
        new_argv.extend(_cxx_runtime_link_args())

    # Also try linking with static library if available
    static_lib = os.path.join(lib_dir, 'lib' + lib_name + '.a')
    if os.path.exists(static_lib):
        print("Also found static library: " + str(static_lib))

    # Insert additional include paths (e.g. lib/ subdirectory where headers live)
    for inc in extra_includes:
        if inc not in new_argv:
            new_argv.insert(4, inc)

    cwd = shared_lib_info['cwd']
    
    # Print the full command to stderr so it's visible even when stdout is captured
    cmd_str = " ".join(shlex.quote(a) for a in new_argv)
    print("Compiling harness with shared lib: " + cmd_str, file=sys.stderr)
    print("DEBUG: Full link command: " + cmd_str)
    p = subprocess.run(new_argv, cwd=cwd)
    output_path = os.path.join(cwd, out_binary)
    if p.returncode != 0:
        sys.exit("Harness compile failed (rc=" + str(p.returncode) + ")")
    if not os.path.exists(output_path):
        if os.path.exists(out_binary):
            output_path = out_binary
        else:
            sys.exit("Harness binary not found at " + str(output_path))
    print("Harness binary created: " + str(output_path))
    return output_path


def compile_harness(plan, harness_src, commands_log, out_binary):
    """Compile the harness using captured build commands with sanitizers."""
    cmds = load_all_commands(commands_log)
    
    project_root = find_project_root(cmds)
    if not project_root:
        project_root = os.getcwd()
    
    print("Project root: " + str(project_root))
    
    # First, check if we can find a library in the project directory
    # This is the most reliable method for simple builds
    project_lib = find_library_in_project(project_root)
    if project_lib:
        print("Found library in project directory: " + str(project_lib['path']))
        return compile_harness_with_project_lib(harness_src, project_lib, out_binary, project_root, cmds)
    
    # Try to find a shared library from build log
    shared_lib = find_shared_library(cmds)
    if shared_lib:
        print("Found shared library: " + str(shared_lib['path']))
        return compile_harness_with_shared_lib(harness_src, shared_lib, out_binary, project_root)
    
    # Try to find a suitable link command (skip test binaries)
    link_cmd = find_link_command(cmds, None, skip_tests=True)
    
    # If no suitable link command, try direct compilation
    if not link_cmd:
        print("No suitable executable link command found (skipped test binaries)")
        print("Trying direct compilation with library object files...")
        return compile_harness_direct(harness_src, cmds, out_binary, project_root)
    
    link_output = link_cmd['argv'][-1] if '-o' not in link_cmd['argv'] else link_cmd['argv'][link_cmd['argv'].index('-o')+1]
    print("Using link command from: " + str(link_cmd['argv'][0]) + " -> " + str(link_output))
    
    argv = list(link_cmd['argv'])
    
    # Find the original output binary name
    original_output = None
    if '-o' in argv:
        idx = argv.index('-o')
        if idx + 1 < len(argv):
            original_output = argv[idx + 1]
    
    # Replace source file with harness and output name
    new_argv = []
    replaced_src = False
    for i, arg in enumerate(argv):
        if not replaced_src and arg.endswith(('.cc', '.cpp', '.c')):
            new_argv.append(harness_src)
            replaced_src = True
        elif arg == original_output:
            new_argv.append(out_binary)
        elif i > 0 and argv[i-1] == '-o' and arg == original_output:
            new_argv.append(arg)
        else:
            new_argv.append(arg)
    
    cwd = link_cmd['cwd']
    
    # Add include path
    include_flag = '-I' + str(project_root)
    parent_include_flag = '-I' + str(os.path.dirname(str(project_root)))
    if include_flag not in new_argv:
        for i, arg in enumerate(new_argv):
            if arg.endswith('clang++') or arg.endswith('g++') or arg.endswith('c++') or \
               arg.endswith('clang') or arg.endswith('gcc'):
                new_argv.insert(i + 1, include_flag)
                break
    if parent_include_flag not in new_argv:
        for i, arg in enumerate(new_argv):
            if arg == include_flag:
                new_argv.insert(i + 1, parent_include_flag)
                break
    
    # Add sanitizer flags
    if not has_sanitizer_flags(new_argv):
        print("Adding sanitizer flags for ASAN/UBSAN and coverage...")
        new_argv = add_sanitizer_flags(new_argv)
    
    # Handle LIB_FUZZING_ENGINE
    lib_fuzzing_engine = os.environ.get('LIB_FUZZING_ENGINE', '')
    if lib_fuzzing_engine and os.path.exists(lib_fuzzing_engine):
        new_argv = [arg for arg in new_argv if not arg.startswith('-lFuzzer')]
        new_argv.append(lib_fuzzing_engine)
        print("Linking with LIB_FUZZING_ENGINE: " + str(lib_fuzzing_engine))
    
    cmd_str_b = " ".join(shlex.quote(a) for a in new_argv)
    print("Compiling harness: " + cmd_str_b)
    print("Compiling harness: " + cmd_str_b, file=sys.stderr)
    p = _run_link_with_fallback(new_argv, cwd)
    output_path = os.path.join(cwd, out_binary)
    if p.returncode != 0:
        sys.exit("Harness compile failed (rc=" + str(p.returncode) + ")")
    if not os.path.exists(output_path):
        if os.path.exists(out_binary):
            output_path = out_binary
        else:
            sys.exit("Harness binary not found at " + str(output_path))
    print("Harness binary created: " + str(output_path))


def _emit_fuzzer_options(out_dir, binary_path, plan_path):
    """Emit a libFuzzer `<binary>.options` file with `max_len` keyed on the
    CVE's CWE class. libFuzzer reads this automatically when the binary
    is invoked. Without it, libFuzzer caps inputs at 4 KB which is too
    small for size-driven (CWE-190) and resource-exhaustion (CWE-770/674)
    CVEs to ever reach the trigger.

    Library-agnostic; CWE-driven only.
    """
    try:
        plan = json.loads(Path(plan_path).read_text(encoding="utf-8"))
    except Exception:
        plan = {}
    entry = plan.get("vuln_entry", {}) if isinstance(plan, dict) else {}
    raw = entry.get("cwe-id") or entry.get("cwe") or []
    if isinstance(raw, str):
        cwes = {c.strip().upper() for c in raw.replace(",", " ").split()
                if c.strip()}
    elif isinstance(raw, list):
        cwes = {str(c).strip().upper() for c in raw if str(c).strip()}
    else:
        cwes = set()
    # Default 64 KB; bump for size-driven / exhaustion CVEs that need MB+
    # inputs; bump further for INT_MAX-reaching size overflows.
    max_len = 65536
    if cwes & {"CWE-190", "CWE-191"}:
        max_len = 1 << 20            # 1 MB
    if cwes & {"CWE-770", "CWE-789", "CWE-674", "CWE-121", "CWE-122"}:
        max_len = max(max_len, 1 << 20)
    options_path = Path(binary_path).with_suffix(
        Path(binary_path).suffix + ".options"
    ) if Path(binary_path).suffix else Path(str(binary_path) + ".options")
    body = "[libfuzzer]\nmax_len = {}\ntimeout = 25\n".format(max_len)
    try:
        options_path.write_text(body)
        print("Wrote fuzzer options: " + str(options_path) +
              " (max_len=" + str(max_len) + ")")
    except Exception as _e:
        pass


def main():
    parser = argparse.ArgumentParser(description="Compile generated harness using captured link recipe")
    parser.add_argument("--log", required=True, help="Path to rf_build_commands.jsonl")
    parser.add_argument("--harness-src", required=True, help="Path to generated fuzzer.cc")
    parser.add_argument("--out-binary", required=True, help="Name of binary to produce (e.g. fuzzer)")
    args = parser.parse_args()

    compile_harness(None, args.harness_src, args.log, args.out_binary)


if __name__ == "__main__":
    main()