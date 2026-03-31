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


def _detect_extra_libs(static_lib_path, lib_name):
    """Probe a static library with nm and return extra -l flags for common
    transitive dependencies whose symbols are undefined."""
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
        ('deflate', '-lz',     {'z', 'zlib'}),
        ('inflate', '-lz',     {'z', 'zlib'}),
        ('compress', '-lz',    {'z', 'zlib'}),
    ]
    extra = []
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
        if lib_name in excluded:
            continue
        if prefix in undef and flag not in extra:
            extra.append(flag)
            print("DEBUG: Auto-detected transitive dependency: " + flag)
    return extra


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
        os.path.join(project_root, 'build'),  # CMake build dir
    ]
    
    for search_dir in search_dirs:
        if not os.path.exists(search_dir):
            continue
            
        for pattern in patterns:
            matches = glob.glob(os.path.join(search_dir, pattern))
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
                    'dir': search_dir,
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
        if os.path.basename(cwd) == 'build':
            return os.path.dirname(cwd)
    return None


def has_sanitizer_flags(argv):
    """Check if the command already has sanitizer flags."""
    for arg in argv:
        if '-fsanitize=' in arg:
            return True
    return False


def add_sanitizer_flags(argv):
    """Add ASAN/UBSAN and fuzzer flags to the command."""
    sanitizer_flags = ['-fsanitize=address,undefined,fuzzer']
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
    print("DEBUG: Extracted include paths: " + str(include_paths))
    
    compiler = 'clang++'
    
    # Build the compile command
    new_argv = [
        compiler,
        '-fsanitize=address,undefined,fuzzer',
        '-fno-omit-frame-pointer',
        '-gline-tables-only',
        '-I' + str(project_root),
        '-o', out_binary,
        harness_src,
    ]
    
    # Add all extracted include paths (for generated headers like zconf.h)
    for inc_path in include_paths:
        inc_flag = '-I' + str(inc_path)
        if inc_flag not in new_argv:
            new_argv.insert(4, inc_flag)
    
    # Add defines from library compile
    if lib_cmd:
        for arg in lib_cmd['argv']:
            if arg.startswith('-D') and ('EXPORT' in arg or 'ENABLE' in arg or 'VISIBILITY' in arg):
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
    
    new_argv.extend(['-lm', '-pthread'])
    
    print("Compiling harness: " + " ".join(shlex.quote(a) for a in new_argv))
    p = subprocess.run(new_argv, cwd=project_root)
    
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
        print("DEBUG: Extracted include paths: " + str(include_paths))
    
    if project_lib['type'] == 'static':
        # Static library - link directly
        new_argv = [
            compiler,
            '-fsanitize=address,undefined,fuzzer',
            '-fno-omit-frame-pointer',
            '-gline-tables-only',
            '-I' + str(project_root),
            '-o', out_binary,
            harness_src,
        ]
        
        # Add extracted include paths (for generated headers like zconf.h)
        for inc_path in include_paths:
            inc_flag = '-I' + str(inc_path)
            if inc_flag not in new_argv:
                new_argv.insert(4, inc_flag)
        
        new_argv.extend([lib_path, '-lm', '-pthread'])
        
        # Auto-detect additional transitive dependencies (e.g. -llzma, -lbz2, -lz)
        new_argv.extend(_detect_extra_libs(lib_path, lib_name))
        
        print("Linking with static library: " + str(lib_path))
    else:
        # Shared library - use -L and -l with rpath
        new_argv = [
            compiler,
            '-fsanitize=address,undefined,fuzzer',
            '-fno-omit-frame-pointer',
            '-gline-tables-only',
            '-I' + str(project_root),
            '-o', out_binary,
            harness_src,
        ]
        
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
        print("Linking with shared library: -L" + str(lib_dir) + " -l" + str(lib_name))
    
    cmd_str = " ".join(shlex.quote(a) for a in new_argv)
    print("Compiling harness: " + cmd_str)
    p = subprocess.run(new_argv, cwd=project_root)
    
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
        new_argv = [
            compiler,
            '-fsanitize=address,undefined,fuzzer',
            '-fno-omit-frame-pointer',
            '-gline-tables-only',
            '-I' + str(project_root),
            '-o', out_binary,
            harness_src,
            static_lib,
            '-lm',
            '-pthread',
        ]
        
        # Auto-detect additional transitive dependencies (e.g. -llzma, -lbz2, -lz)
        new_argv.extend(_detect_extra_libs(static_lib, lib_name))
        
        new_argv.append('-ldl')
    elif actual_lib_path:
        print("DEBUG: Using shared library: " + str(actual_lib_path))
        
        # Link directly with the .so file - always use --no-as-needed for shared libs
        new_argv = [
            compiler,
            '-fsanitize=address,undefined,fuzzer',
            '-fno-omit-frame-pointer',
            '-gline-tables-only',
            '-I' + str(project_root),
            '-o', out_binary,
            harness_src,
            '-Wl,--no-as-needed',
            actual_lib_path,
            '-Wl,--as-needed',
            '-Wl,-rpath,' + str(lib_dir),
            '-lm',
            '-pthread',
            '-ldl',  # zlib often needed
        ]
    else:
        # Fallback to standard -l linking
        print("DEBUG: Using fallback -l linking")
        new_argv = [
            compiler,
            '-fsanitize=address,undefined,fuzzer',
            '-fno-omit-frame-pointer',
            '-gline-tables-only',
            '-I' + str(project_root),
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
        ]
    
    # Also try linking with static library if available
    static_lib = os.path.join(lib_dir, 'lib' + lib_name + '.a')
    if os.path.exists(static_lib):
        print("Also found static library: " + str(static_lib))
    
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
    if include_flag not in new_argv:
        for i, arg in enumerate(new_argv):
            if arg.endswith('clang++') or arg.endswith('g++') or arg.endswith('c++') or \
               arg.endswith('clang') or arg.endswith('gcc'):
                new_argv.insert(i + 1, include_flag)
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
    
    print("Compiling harness: " + " ".join(shlex.quote(a) for a in new_argv))
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


def main():
    parser = argparse.ArgumentParser(description="Compile generated harness using captured link recipe")
    parser.add_argument("--log", required=True, help="Path to rf_build_commands.jsonl")
    parser.add_argument("--harness-src", required=True, help="Path to generated fuzzer.cc")
    parser.add_argument("--out-binary", required=True, help="Name of binary to produce (e.g. fuzzer)")
    args = parser.parse_args()

    compile_harness(None, args.harness_src, args.log, args.out_binary)


if __name__ == "__main__":
    main()