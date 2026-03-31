#!/usr/bin/env python3
import argparse
import json
import os
from clang import cindex
from typing import List, Set, Tuple

def load_compile_commands(log_path: str) -> List[dict]:
    cmds = []
    if not os.path.exists(log_path):
        return cmds
    with open(log_path, 'r') as f:
        for line in f:
            try:
                entry = json.loads(line)
                cmds.append(entry.get('argv', []))
            except Exception:
                continue
    return cmds

def find_public_include_dirs(commands: List[List[str]], project_root: str) -> Set[str]:
    """Find project-specific include directories (exclude system paths)."""
    project_root_abs = os.path.abspath(project_root)
    include_dirs = set()
    
    for argv in commands:
        for i, arg in enumerate(argv):
            if arg.startswith('-I') and len(arg) > 2:
                path = arg[2:]
            elif arg == '-I' and i+1 < len(argv):
                path = argv[i+1]
            else:
                continue
                
            # Resolve to absolute path
            if os.path.isabs(path):
                abs_path = path
            else:
                abs_path = os.path.abspath(os.path.join(project_root, path))
            
            # Only include if it's within the project root (exclude system paths)
            if os.path.isdir(abs_path) and abs_path.startswith(project_root_abs):
                include_dirs.add(abs_path)
    
    # Also add common project-specific include directories
    for cand in ['include', 'includes', 'inc', 'lib', 'src']:
        path = os.path.join(project_root, cand)
        abs_path = os.path.abspath(path)
        if os.path.isdir(abs_path):
            include_dirs.add(abs_path)
    
    # Add project root itself (for headers in root like cJSON.h)
    include_dirs.add(project_root_abs)
    
    return include_dirs

def extract_public_usrs(include_dirs: Set[str]) -> Set[str]:
    index = cindex.Index.create()
    public_usrs = set()
    
    # Resolve include_dirs to absolute paths for comparison
    include_dirs_abs = {os.path.abspath(d) for d in include_dirs}
    
    for inc in include_dirs:
        for root, _, files in os.walk(inc):
            for fn in files:
                if fn.endswith(('.h', '.hpp', '.hh')):
                    path = os.path.join(root, fn)
                    path_abs = os.path.abspath(path)
                    try:
                        tu = index.parse(path, args=[])
                    except Exception:
                        continue
                    for node in tu.cursor.get_children():
                        # Public APIs are typically declared (not defined) in headers.
                        # Collect function/method declarations regardless of definition.
                        if not (node.kind.is_declaration() and node.kind.name.endswith('DECL')):
                            continue

                        # Filter to callable-like declarations.
                        if node.kind.name not in {
                            "FUNCTION_DECL",
                            "CXX_METHOD",
                            "CONSTRUCTOR",
                            "DESTRUCTOR",
                            "FUNCTION_TEMPLATE",
                        }:
                            continue

                        # CRITICAL: Only include functions declared in THIS header file
                        # Skip functions from included system headers
                        if node.location and node.location.file:
                            node_file = os.path.abspath(node.location.file.name)
                            if node_file != path_abs:
                                # This function is from an included header, skip it
                                continue

                        usr = node.get_usr()
                        if usr:
                            # Filter out USRs from source files (they contain .c@, .cc@, etc.)
                            # These are internal/static functions, not public API declarations
                            if any(ext in usr for ext in ['.c@', '.cc@', '.cpp@', '.cxx@']):
                                continue
                            public_usrs.add(usr)
    return public_usrs

def extract_function_signatures(include_dirs: Set[str], export_macros: Set[str] = None, public_only: bool = True) -> dict:
    """
    Extract function signatures from header files.
    Returns dict: func_name -> [(type, name), ...] for parameters.
    Includes ALL functions declared in headers, even those with no parameters.
    ONLY extracts functions declared directly in the header file (not from included system headers).
    Uses both libclang and regex fallback for macro-wrapped declarations.
    
    Args:
        include_dirs: Set of directories to scan for headers
        export_macros: Optional set of export macro names (e.g., {'PNG_EXPORT', 'ZLIB_EXPORT'})
                       If provided, prefer functions declared with these macros.
        public_only: If True, skip private/internal headers (e.g., *priv.h, *internal.h)
    """
    import re
    
    # Private header patterns - these contain internal functions
    private_header_patterns = [
        r'priv\.h$',           # pngpriv.h, zlibpriv.h
        r'private\.h$',        # private.h
        r'internal\.h$',       # internal.h
        r'_priv\.h$',          # lib_priv.h
        r'_private\.h$',       # lib_private.h
        r'_internal\.h$',      # lib_internal.h
        r'pstream\.h$',        # often internal
        r'detail[/\\]',        # C++ detail headers
        r'impl[/\\]',          # C++ impl headers
    ]
    index = cindex.Index.create()
    signatures = {}
    
    # Resolve include_dirs to absolute paths for comparison
    include_dirs_abs = {os.path.abspath(d) for d in include_dirs}
    
    for inc in include_dirs:
        for root, _, files in os.walk(inc):
            for fn in files:
                if fn.endswith(('.h', '.hpp', '.hh')):
                    path = os.path.join(root, fn)
                    path_abs = os.path.abspath(path)
                    
                    # Skip private/internal headers if public_only is True
                    if public_only:
                        is_private = False
                        for pattern in private_header_patterns:
                            if re.search(pattern, path):
                                is_private = True
                                break
                        if is_private:
                            continue
                    
                    # Read file content for regex fallback
                    content = None
                    try:
                        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                    except Exception:
                        content = None
                    
                    # Method 1: libclang parsing
                    try:
                        tu = index.parse(path, args=[])
                        for node in tu.cursor.get_children():
                            if node.kind.name == "FUNCTION_DECL":
                                # CRITICAL: Only include functions declared in THIS header file
                                # Skip functions from included system headers
                                if node.location and node.location.file:
                                    node_file = os.path.abspath(node.location.file.name)
                                    if node_file != path_abs:
                                        # This function is from an included header, skip it
                                        continue
                                
                                func_name = node.spelling
                                if not func_name:
                                    continue
                                # Extract parameters
                                params = []
                                for child in node.get_children():
                                    if child.kind.name == "PARM_DECL":
                                        param_name = child.spelling or ""
                                        param_type = child.type.spelling or ""
                                        if param_type:
                                            params.append((param_type, param_name))
                                # Include ALL functions (even with empty params)
                                signatures[func_name] = params
                    except Exception as e:
                        pass
                    
                    # Method 2: Regex fallback for macro-wrapped declarations.
                    if content:
                        import re
                        
                        # Strip C/C++ comments to avoid matching text inside them
                        stripped = re.sub(r'/\*.*?\*/', ' ', content, flags=re.DOTALL)
                        stripped = re.sub(r'//[^\n]*', ' ', stripped)
                        content = stripped
                        
                        # Pattern 1: Standard C function declaration ending with ;
                        # func_name(args);
                        for match in re.finditer(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(([^)]*)\)\s*;', content):
                            func_name = match.group(1)
                            if func_name in ['if', 'while', 'for', 'switch', 'return', 'sizeof', 'typedef', 'struct', 'enum', 'union']:
                                continue
                            args_str = match.group(2)
                            params = parse_params_string(args_str)
                            if func_name not in signatures:  # Don't overwrite libclang results
                                signatures[func_name] = params
                        
                        # Pattern 2: Macro-wrapped function declarations
                        # MACRO(return_type) func_name(args) MACRO;
                        for match in re.finditer(r'\b([A-Z_][A-Z0-9_]*\s+)?([a-zA-Z_][a-zA-Z0-9_]*)\s*\(([^)]*)\)', content):
                            func_name = match.group(2)
                            if func_name in ['if', 'while', 'for', 'switch', 'return', 'sizeof', 'typedef', 'struct', 'enum', 'union']:
                                continue
                            if func_name.startswith('_') or func_name.startswith('Z_') or func_name.startswith('OF'):
                                continue
                            # Check if this looks like a function declaration (not a macro call)
                            if func_name not in signatures:
                                args_str = match.group(3)
                                params = parse_params_string(args_str)
                                signatures[func_name] = params
                        
                        # Pattern 3: Look for generic export-style declarations
                        # EXTERN ... LIB_EXPORT func_name ... ;
                        for match in re.finditer(r'[A-Z_][A-Z0-9_]*EXPORT[A-Z0-9_]*\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:[A-Z_][A-Z0-9_]*\s*)?\(', content):
                            func_name = match.group(1)
                            if func_name not in signatures:
                                signatures[func_name] = []
                        
                        # Pattern 4: Legacy macro wrappers like OF((args))
                        # func_name OF((args))
                        for match in re.finditer(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s+OF\s*\(\s*\(([^)]*)\)', content):
                            func_name = match.group(1)
                            if func_name in ['if', 'while', 'for', 'switch', 'return', 'sizeof']:
                                continue
                            if func_name not in signatures:
                                args_str = match.group(2)
                                params = parse_params_string(args_str)
                                signatures[func_name] = params
    
    return signatures


def extract_exported_symbols_from_library(library_path: str) -> Set[str]:
    """
    Extract exported (public) symbols from a compiled shared library or object file.
    Uses nm (Linux) or objdump (fallback) to get the symbol table.
    
    This is the most reliable way to determine if a function is a public API:
    - If it's exported, it's meant to be called from outside the library.
    - If it's not exported (or marked as local/hidden), it's internal.
    """
    import subprocess
    import re
    
    exported = set()
    
    if not os.path.exists(library_path):
        print("DEBUG: Library not found: " + library_path)
        return exported
    
    # Skip static libraries (.a) - they don't have dynamic symbol tables
    # and nm output is complex (archive format)
    if library_path.endswith('.a') or library_path.endswith('.lib'):
        # For static libs, we'll try nm but it's less reliable
        pass
    
    # Method 1: Try readelf -sW (most reliable for .so files)
    # readelf shows the actual symbol table with visibility info
    try:
        proc = subprocess.Popen(
            ['readelf', '-sW', library_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        stdout, stderr = proc.communicate()
        if proc.returncode == 0:
            output = stdout.decode('utf-8', errors='ignore')
            # readelf -sW output format:
            #    Num:    Value          Size Type    Bind   Vis      Ndx Name
            #    42: 000000000001a000   1234 FUNC    GLOBAL DEFAULT   13 png_read_info
            for line in output.split('\n'):
                if 'FUNC' in line or 'OBJECT' in line:
                    parts = line.split()
                    if len(parts) >= 8:
                        # Check if GLOBAL or WEAK binding (exported)
                        # and DEFAULT visibility (not hidden)
                        bind = parts[4] if len(parts) > 4 else ''
                        vis = parts[5] if len(parts) > 5 else ''
                        name = parts[7] if len(parts) > 7 else ''
                        if bind in ['GLOBAL', 'WEAK'] and vis == 'DEFAULT' and name:
                            exported.add(name)
            if exported:
                return exported
    except Exception as e:
        print("DEBUG: readelf failed for " + library_path + ": " + str(e))
    
    # Method 2: Try nm -D (dynamic symbols)
    try:
        proc = subprocess.Popen(
            ['nm', '-D', '--defined-only', library_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        stdout, stderr = proc.communicate()
        if proc.returncode == 0:
            output = stdout.decode('utf-8', errors='ignore')
            # nm -D output: "0000000000001000 T function_name"
            for line in output.split('\n'):
                parts = line.strip().split()
                if len(parts) >= 3:
                    sym_type = parts[1] if len(parts[1]) == 1 else parts[1][-1]
                    if sym_type in ['T', 'D', 'B', 'R', 't', 'd', 'b', 'r']:
                        # Uppercase = global, lowercase = local
                        if sym_type.isupper():
                            exported.add(parts[-1])
                elif len(parts) == 2:
                    sym_type = parts[0] if len(parts[0]) == 1 else parts[0][-1]
                    if sym_type.isupper() and sym_type in ['T', 'D', 'B', 'R']:
                        exported.add(parts[-1])
            if exported:
                return exported
    except Exception as e:
        print("DEBUG: nm -D failed for " + library_path + ": " + str(e))
    
    # Method 3: Try nm without -D (static library fallback)
    try:
        proc = subprocess.Popen(
            ['nm', library_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        stdout, stderr = proc.communicate()
        if proc.returncode == 0:
            output = stdout.decode('utf-8', errors='ignore')
            for line in output.split('\n'):
                # For .a files, format is: archive.a:file.o:
                # Followed by: address T name
                if ':' in line and '.o:' in line:
                    continue  # Skip archive member lines
                parts = line.strip().split()
                if len(parts) >= 3:
                    sym_type = parts[1] if len(parts[1]) == 1 else parts[1][-1]
                    if sym_type.isupper() and sym_type in ['T', 'D', 'B', 'R']:
                        exported.add(parts[-1])
                elif len(parts) == 2:
                    sym_type = parts[0] if len(parts[0]) == 1 else parts[0][-1]
                    if sym_type.isupper() and sym_type in ['T', 'D', 'B', 'R']:
                        exported.add(parts[-1])
    except Exception as e:
        print("DEBUG: nm failed for " + library_path + ": " + str(e))
    
    print("DEBUG: extract_exported_symbols_from_library(" + library_path + ") found " + str(len(exported)) + " symbols")
    return exported


def find_shared_libraries(project_root: str) -> Tuple[List[str], List[str]]:
    """
    Find compiled shared libraries (.so, .dylib, .dll) and static libraries (.a) in the project.
    Looks in common build directories.
    
    Returns: (shared_libs, static_libs) - shared libraries are prioritized because
             they have proper symbol visibility, while static libraries export ALL symbols.
    """
    shared_libs = []
    static_libs = []
    
    # Common build output directories
    build_dirs = ['build', 'out', 'lib', 'libs', '.libs', 'lib/.libs']
    
    for build_dir in build_dirs:
        full_path = os.path.join(project_root, build_dir)
        if os.path.isdir(full_path):
            for root, dirs, files in os.walk(full_path):
                for f in files:
                    lib_path = os.path.join(root, f)
                    if f.endswith(('.so', '.dylib', '.dll')):
                        shared_libs.append(lib_path)
                    elif f.endswith(('.a', '.lib')):
                        static_libs.append(lib_path)
    
    # Also check project root
    for root, dirs, files in os.walk(project_root):
        # Skip deep subdirectories to avoid finding test libraries
        depth = root[len(project_root):].count(os.sep)
        if depth <= 2:
            for f in files:
                lib_path = os.path.join(root, f)
                # Skip test libraries
                if 'test' not in f.lower() and 'example' not in f.lower():
                    if f.endswith(('.so', '.dylib', '.dll')):
                        shared_libs.append(lib_path)
                    elif f.endswith(('.a', '.lib')):
                        static_libs.append(lib_path)
    
    # Remove duplicates while preserving order
    seen = set()
    unique_shared = []
    for lib in shared_libs:
        if lib not in seen:
            seen.add(lib)
            unique_shared.append(lib)
    
    unique_static = []
    for lib in static_libs:
        if lib not in seen:
            seen.add(lib)
            unique_static.append(lib)
    
    return unique_shared, unique_static


def get_exported_symbols(project_root: str) -> Tuple[Set[str], List[str]]:
    """
    Get all exported symbols from compiled libraries in the project.
    This gives us the TRUE public APIs.
    
    IMPORTANT: Prioritizes shared libraries (.so) over static libraries (.a)
    because static libraries export ALL symbols (including internal ones),
    while shared libraries properly hide internal symbols via visibility attributes.
    
    Returns: (exported_symbols, libraries_found)
    """
    shared_libs, static_libs = find_shared_libraries(project_root)
    
    print("DEBUG: get_exported_symbols: Found " + str(len(shared_libs)) + " shared libs, " + str(len(static_libs)) + " static libs")
    
    exported = set()
    
    # PRIORITY 1: Use shared libraries ONLY (they have proper symbol visibility)
    # Shared libraries hide internal symbols, so only true public APIs are exported
    if shared_libs:
        for lib in shared_libs:
            symbols = extract_exported_symbols_from_library(lib)
            print("DEBUG: Shared lib " + lib + " has " + str(len(symbols)) + " exported symbols")
            if symbols:
                print("DEBUG: Sample symbols: " + str(list(symbols)[:10]))
            exported.update(symbols)
        
        if exported:
            print("DEBUG: Using symbols from shared libraries only (proper visibility)")
            # Filter and return
            return _filter_exported_symbols(exported), shared_libs
    
    # PRIORITY 2: Fall back to static libraries if no shared libs found
    # WARNING: Static libraries export ALL symbols, including internal ones
    # This is less reliable but better than nothing
    if static_libs:
        print("DEBUG: No shared libraries found, falling back to static libraries (may include internal symbols)")
        for lib in static_libs:
            symbols = extract_exported_symbols_from_library(lib)
            print("DEBUG: Static lib " + lib + " has " + str(len(symbols)) + " exported symbols")
            if symbols:
                print("DEBUG: Sample symbols: " + str(list(symbols)[:10]))
            exported.update(symbols)
    
    return _filter_exported_symbols(exported), shared_libs + static_libs


def _filter_exported_symbols(exported: Set[str]) -> Set[str]:
    """Filter out system symbols and strip version suffixes from exported symbols."""
    # Filter out common system/c-runtime symbols that aren't library APIs
    system_symbols = {
        '_init', '_fini', '__cxa_finalize', '__cxa_atexit', '_Jv_RegisterClasses',
        '_ITM_deregisterTMCloneTable', '_ITM_registerTMCloneTable',
        '_GLOBAL_OFFSET_TABLE_', '__gmon_start__', '_start', 'main',
        '__libc_csu_init', '__libc_csu_fini', '__libc_start_main',
        '_dl_relocate_static_pie', '__assert_fail', '__errno_location',
        # Also filter out common libc/libm symbols that might leak through
        'fopen', 'fclose', 'fread', 'fwrite', 'malloc', 'free', 'calloc', 'realloc',
        'printf', 'fprintf', 'sprintf', 'snprintf', 'memcpy', 'memmove', 'memset',
        'strlen', 'strcmp', 'strcpy', 'strcat', 'strncmp', 'strncpy', 'strncat',
    }
    
    stripped_exported = set()
    for s in exported:
        # Remove @@VERSION suffix (e.g., png_read_info@@PNG16_0 -> png_read_info)
        if '@@' in s:
            s = s.split('@@')[0]
        # Filter out symbols starting with underscore (usually internal)
        # and system symbols
        if s not in system_symbols and not s.startswith('_'):
            stripped_exported.add(s)
    
    return stripped_exported


def detect_export_macros(content: str) -> Set[str]:
    """
    Detect export macros used in a header file.
    Common patterns: *_EXPORT, *_API, and visibility attributes.
    """
    import re
    macros = set()
    
    # Pattern 1: #define PREFIX_EXPORT ... (visibility or export macros)
    for match in re.finditer(r'#define\s+([A-Z_][A-Z0-9_]*EXPORT[A-Z0-9_]*)\s', content):
        macros.add(match.group(1))
    
    # Pattern 2: #define PREFIX_API ... 
    for match in re.finditer(r'#define\s+([A-Z_][A-Z0-9_]*API[A-Z0-9_]*)\s', content):
        macros.add(match.group(1))
    
    # Pattern 3: __declspec(dllexport) or __attribute__((visibility("default")))
    if '__declspec(dllexport)' in content or 'visibility("default")' in content:
        macros.add('__EXPORT__')
    
    return macros

def extract_exported_functions(include_dirs: Set[str]) -> dict:
    """
    Extract only EXPORTED function signatures from header files.
    This distinguishes between:
    - Public APIs: Functions marked with export macros or visibility attributes
    - Internal functions: Functions declared in headers but not exported
    
    Returns dict: func_name -> [(type, name), ...] for parameters.
    """
    import re
    signatures = {}
    
    for inc in include_dirs:
        for root, _, files in os.walk(inc):
            for fn in files:
                if fn.endswith(('.h', '.hpp', '.hh')):
                    path = os.path.join(root, fn)
                    
                    try:
                        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                    except Exception:
                        continue
                    
                    # Detect export macros used in this file
                    export_macros = detect_export_macros(content)
                    
                    # Common export macro patterns, expressed generically rather than
                    # special-casing individual libraries.
                    common_export_patterns = [
                        # Generic export macro with multiple leading metadata/type fields
                        r'([A-Z_][A-Z0-9_]*EXPORT[A-Z0-9_]*)\s*\(\s*(?:[^,]+\s*,\s*){2,}([a-zA-Z_][a-zA-Z0-9_]*)\s*,',
                        # Generic export macro with (type, name) style arguments
                        r'([A-Z_][A-Z0-9_]*EXPORT[A-Z0-9_]*)\s*\(\s*[^,]+\s*,\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\)',
                        # Generic export macro preceding the function name directly
                        r'([A-Z_][A-Z0-9_]*EXPORT[A-Z0-9_]*)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(',
                        # Generic external declaration followed by an export macro and function name
                        r'[A-Z_][A-Z0-9_]*\s+\w+\s+([A-Z_][A-Z0-9_]*EXPORT[A-Z0-9_]*)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(',
                        # Generic: LIB_API type func(
                        r'([A-Z_][A-Z0-9_]*API[A-Z0-9_]*)\s+\w+\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(',
                        # Windows: __declspec(dllexport) type func(
                        r'__declspec\(dllexport\)\s+\w+\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(',
                        # GCC: __attribute__((visibility("default"))) type func(
                        r'__attribute__\s*\(\(visibility\s*\("default"\)\)\)\s+\w+\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(',
                    ]
                    
                    # Extract functions with export macros
                    for pattern in common_export_patterns:
                        for match in re.finditer(pattern, content):
                            # Handle patterns with 1 or 2 groups
                            if match.lastindex == 1:
                                func_name = match.group(1)
                            elif match.lastindex == 2:
                                func_name = match.group(2)
                            else:
                                continue
                            
                            if func_name and func_name not in ['if', 'while', 'for', 'switch', 'return', 'sizeof']:
                                if func_name not in signatures:
                                    signatures[func_name] = []
                    
                    # Also check for any macro-detected exports
                    for macro in export_macros:
                        # Pattern: MACRO(type, func_name) or MACRO func_name(
                        # Note: Using format() instead of f-string for Python 3.5 compatibility
                        escaped_macro = re.escape(macro)
                        pattern = escaped_macro + r'\s*\([^,]*,\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\)'
                        for match in re.finditer(pattern, content):
                            func_name = match.group(1)
                            if func_name not in signatures:
                                signatures[func_name] = []
                        
                        pattern2 = escaped_macro + r'\s+\w+\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\('
                        for match in re.finditer(pattern2, content):
                            func_name = match.group(1)
                            if func_name not in signatures:
                                signatures[func_name] = []
    
    return signatures

def is_internal_function_name(func_name: str) -> bool:
    """
    Determine if a function name looks like an internal function.
    
    Internal patterns (NOT public APIs):
    - Starts with underscore: _internal_func
    - Starts with lowercase verb followed by underscore: handle_eXIf, process_data
    - Contains 'internal' or 'private': internal_func, private_func
    - Starts with uppercase followed by lowercase (CamelCase) without underscore separator: XmlParse, JsonDecode
      (Public APIs typically use: XML_parse, JSON_decode or xml_parse, json_decode)
    
    Public API patterns:
    - ALL_CAPS prefix with underscore: XML_Parse, PNG_read_info, JSON_parse
    - lowercase prefix with underscore: png_read_info, expat_parse
    - Single word verbs: parse, decode, encode
    """
    if not func_name or len(func_name) < 3:
        return False
    
    import re
    
    # Pattern 1: Starts with underscore or double underscore
    if func_name.startswith('_'):
        return True
    
    # Pattern 2: Contains 'internal' or 'private'
    if 'internal' in func_name.lower() or 'private' in func_name.lower():
        return True
    
    # Pattern 3: Check for internal verb patterns after library prefix
    # These are STRONG indicators of internal functions even with library prefix:
    # - handle_* : chunk handlers, event handlers (e.g., png_handle_eXIf, xml_handle_entity)
    # - do_* : internal action functions (e.g., png_do_read_transformations)
    # - process_* : internal processing (e.g., png_process_IDAT_data)
    # - internal_* : explicitly marked internal
    # - private_* : explicitly marked private
    #
    # NOTE: We do NOT include read_, write_, parse_, check_, etc. here because
    # these are common in public APIs: png_read_info, png_write_row, xml_parse, etc.
    strong_internal_verbs = ['handle_', 'do_', 'process_', 'internal_', 'private_']
    
    # Extract the part after the first underscore (if any)
    if '_' in func_name:
        parts = func_name.split('_', 1)
        if len(parts) > 1:
            after_prefix = parts[1]
            # Check if the part after prefix starts with a STRONG internal verb
            for verb in strong_internal_verbs:
                if after_prefix.startswith(verb):
                    return True
    
    # Pattern 3b: Distinguish namespace-like prefixes from action verbs.
    # A name like handle_chunk is usually internal, while foo_parse is often public.
    lowercase_verb_pattern = r'^[a-z]+_[a-z]'
    if re.match(lowercase_verb_pattern, func_name):
        action_like_prefixes = {
            'handle', 'process', 'parse', 'read', 'write', 'check', 'decode',
            'encode', 'update', 'open', 'close', 'init', 'create', 'destroy',
            'free', 'set', 'get', 'load', 'save', 'convert'
        }
        prefix = func_name.split('_')[0].lower()
        if prefix in action_like_prefixes:
            return True
    
    # Pattern 4: CamelCase without underscore (usually internal)
    # e.g., XmlParse, JsonDecode, PngHandle
    # Public APIs typically use underscores: XML_Parse, JSON_decode, png_read_info
    if re.match(r'^[A-Z][a-z]+[A-Z]', func_name):
        # CamelCase starting with capital - likely internal class method or internal function
        return True
    
    # Pattern 5: Functions starting with uppercase followed by lowercase verb
    # e.g., Handle_chunk, Process_data (usually internal callbacks)
    if re.match(r'^[A-Z][a-z]+_[a-z]', func_name):
        return True
    
    return False


def _looks_like_c_type(text):
    """Quick check: does text plausibly look like a C type, not prose or string literal?"""
    import re
    if not text:
        return False
    # Reject if it contains quote characters (string literal fragments)
    if '"' in text or "'" in text:
        return False
    # Reject if it looks like an English phrase (4+ consecutive lowercase words)
    if re.search(r'[a-z]+\s+[a-z]+\s+[a-z]+\s+[a-z]+', text):
        return False
    # Reject if it starts with a common English word that isn't a C type
    first_word = text.split()[0].lower() if text.split() else ''
    _PROSE_WORDS = frozenset([
        'if', 'the', 'a', 'an', 'is', 'has', 'been', 'previously', 'or',
        'and', 'not', 'this', 'that', 'with', 'from', 'to', 'for', 'of',
        'when', 'where', 'which', 'file', 'should', 'must', 'can', 'may',
    ])
    if first_word in _PROSE_WORDS:
        return False
    return True


def parse_params_string(args_str: str) -> list:
    """Parse a parameter string like 'int a, char *b' into list of (type, name) tuples."""
    params = []
    if not args_str or args_str.strip() == '' or args_str.strip() == 'void':
        return params
    
    # Split by comma, handling nested types
    depth = 0
    current = ''
    parts = []
    for c in args_str:
        if c == '(' or c == '<' or c == '[':
            depth += 1
        elif c == ')' or c == '>' or c == ']':
            depth -= 1
        elif c == ',' and depth == 0:
            parts.append(current.strip())
            current = ''
            continue
        current += c
    if current.strip():
        parts.append(current.strip())
    
    for part in parts:
        part = part.strip()
        if not part:
            continue
        
        # Try to split into type and name
        tokens = part.split()
        if len(tokens) >= 2:
            # Last token is usually the name
            param_name = tokens[-1].lstrip('*')
            param_type = ' '.join(tokens[:-1])
            if param_name and param_type:
                # Reject if the type looks like prose, not a C type
                if not _looks_like_c_type(param_type):
                    continue
                params.append((param_type, param_name))
        elif len(tokens) == 1:
            # Just a type, no name (common in C prototypes)
            pass
    
    return params


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Discover public API USRs from headers")
    parser.add_argument('--log', required=True, help="Path to rf_build_commands.jsonl")
    parser.add_argument('--root', required=True, help="Project root directory")
    parser.add_argument('--signatures', action='store_true', help="Output function signatures instead of USRs")
    args = parser.parse_args()

    cmds = load_compile_commands(args.log)
    public_dirs = find_public_include_dirs(cmds, args.root)
    
    if args.signatures:
        sigs = extract_function_signatures(public_dirs)
        print(json.dumps(sigs, indent=2))
    else:
        usrs = extract_public_usrs(public_dirs)
        print(json.dumps(sorted(usrs), indent=2))
