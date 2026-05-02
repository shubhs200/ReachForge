#!/usr/bin/env python3
"""
LLVM IR-based callgraph construction with KELP-style function pointer resolution.
Parses LLVM IR text format (.ll files) to build a precise callgraph.
"""
import os
import re
import json
from typing import Dict, List, Set, Tuple, Optional
from collections import defaultdict


class LLVMCallGraphBuilder:
    """
    Build callgraph from LLVM IR text format.
    Implements KELP-style function pointer resolution:
    1. Track address-taken functions (store @func, ...)
    2. Track function pointer field assignments
    3. Resolve indirect calls via pointer analysis
    4. Track parameter types for data-flow scoring
    """
    
    def __init__(self, max_targets_per_call=24):
        # Function info
        self.functions = {}  # name -> {defined: bool, location: str, params: [(type, name)]}
        
        # Callgraph edges
        self.adjacency = defaultdict(set)  # caller -> set of callees
        
        # KELP data structures
        self.address_taken = defaultdict(list)  # func_name -> [locations where &func is stored]
        self.func_ptr_stores = []  # [(ptr_name, func_name, location, owning_func)]
        self.indirect_calls = []  # [(caller, ptr_name, location)]
        self.func_ptr_loads = []  # [(dst_name, src_name, location)] - loads from memory
        
        # Pointer analysis: map (owning_func, pointer_name) to possible functions.
        # SSA names like %43 are local to a function, so we scope by function to
        # avoid conflating unrelated variables that share a numeric name.
        self.pointer_targets = defaultdict(set)  # (func, ptr_name) -> {func_names}
        
        # Configurable limit: indirect calls resolving to more than this many
        # targets are discarded as likely imprecise (e.g. generic callback
        # registries).  Default 24 is the largest observed dispatch table size
        # in our benchmark libraries (expat's 22 parser handlers).
        self.max_targets_per_call = max_targets_per_call
        
        # Parameter flow tracking for path scoring
        # call_args[(caller, callee)] = [(caller_param_idx, callee_param_idx), ...]
        self.call_args = defaultdict(list)
        self.call_sites = defaultdict(list)  # (caller, callee) -> [[arg1, arg2, ...], ...]
        # func_params[func_name] = [(type, name), ...]
        self.func_params = {}
        
        # Regex patterns for LLVM IR
        # Function definition: handle multi-line by matching opening parenthesis to matching close
        # Pattern handles: define internal fastcc void @func(%struct* %arg, i8* %data) {
        self.func_def_pattern = re.compile(r'^define\s+.*?@([a-zA-Z_][a-zA-Z0-9_]*)\s*\(')
        self.func_decl_pattern = re.compile(r'^declare\s+.*?@([a-zA-Z_][a-zA-Z0-9_]*)\s*\(')
        self.direct_call_pattern = re.compile(r'(?:call|invoke)\s+[^@]*@([a-zA-Z_][a-zA-Z0-9_]*)\s*\(([^)]*)\)')
        # Indirect calls in LLVM IR look like: call i32 %5(i8* %6) or call i32 %funcptr(...)
        # Also match invoke (used in C++ code with exception handling)
        # Match both numbered (%5) and named (%funcptr) locals
        self.indirect_call_pattern = re.compile(r'(?:call|invoke)\s+[^@]*?%([a-zA-Z0-9_.]+)\s*\(')
        # Store of function address: store ... @func, ... %ptr
        # Use greedy .* for the destination register so we skip past %struct.X
        # type annotations and capture the actual register operand (the last
        # %name on the line).
        self.store_pattern = re.compile(r'store\s+.*?@([a-zA-Z_][a-zA-Z0-9_]*)\s*,.*%([a-zA-Z0-9_.]+)')
        # Store of pointer to pointer: store %src, %dst
        self.store_ptr_pattern = re.compile(r'store\s+[^%]*%([a-zA-Z0-9_.]+)\s*,\s*[^%]*%([a-zA-Z0-9_.]+)')
        # Load instruction: %dst = load ... %src  OR  %dst = load ... @global
        # The source can be a local register (%name) or a global variable (@name).
        # Global loads are common for configurable function pointers like @xmlMalloc.
        # Use greedy .* so we skip past %struct.X type annotations and capture
        # the actual source register (the last %name or @name on the line).
        self.load_pattern = re.compile(r'%([a-zA-Z0-9_.]+)\s*=\s*load\s+.*[%@]([a-zA-Z0-9_.]+)')
        # Companion pattern to detect when the source is a global (starts with @)
        self.load_global_pattern = re.compile(r'%([a-zA-Z0-9_.]+)\s*=\s*load\s+.*?@([a-zA-Z_][a-zA-Z0-9_.]*)')
        # GEP (getelementptr) pattern for struct-field function pointer tracking.
        # Captures: dst_register, struct_type, base_register, field_index
        # Example: %6 = getelementptr inbounds %struct.XML_ParserStruct, %struct.XML_ParserStruct* %5, i32 0, i32 45
        self.gep_pattern = re.compile(
            r'%([a-zA-Z0-9_.]+)\s*=\s*getelementptr\s+(?:inbounds\s+)?'
            r'(%(?:struct|class|union)\.[a-zA-Z0-9_.]+)\s*,'
            r'\s*[^,]*%([a-zA-Z0-9_.]+)\s*,'
            r'.*?(?:i32|i64)\s+0\s*,\s*(?:i32|i64)\s+(\d+)'
        )
        # Maps (owning_func, register) -> (struct_type, field_index)
        self.gep_info = {}
        # Maps (owning_func, dst_register) -> (owning_func, base_register)
        # Used for nested GEP chaining (e.g. ctx->handlers->on_data)
        self.gep_base = {}
        # Maps (struct_type, field_index) -> {function_names stored into that field}
        self.struct_field_targets = defaultdict(set)
        
        # ---- Vtable (C++ virtual dispatch) support ----
        # Maps vtable global name -> [function_name_or_None, ...] indexed by slot
        self.vtable_entries = {}   # e.g. '_ZTV4Base' -> ['_ZN4Base3fooEv', ...]
        # Maps (owning_func, register) -> (vtable_global, slot_index)
        # Populated when we see the load-vptr → GEP-vtable → load-fptr pattern
        self.vtable_slot_info = {}
        # GEP pattern for vtable slot indexing (bare-pointer GEP without struct type):
        #   %vfn = getelementptr inbounds ptr, ptr %vtable, i64 2
        # or older typed-pointer form:
        #   %vfn = getelementptr inbounds i8* (%class.Base*)**, i8* (%class.Base*)*** %vtable, i64 2
        self.vtable_gep_pattern = re.compile(
            r'%([a-zA-Z0-9_.]+)\s*=\s*getelementptr\s+(?:inbounds\s+)?'
            r'(?:ptr|[^,]+\*+)\s*,\s*(?:ptr|[^,]+\*+)\s+%([a-zA-Z0-9_.]+)\s*,\s*'
            r'(?:i32|i64)\s+(\d+)\s*$'
        )
        
        # Track which registers point to which memory locations
        self.register_to_memory = {}  # register -> memory_location

        self.control_param_keywords = ['mode', 'type', 'flag', 'flags', 'strategy', 'method',
                           'level', 'window', 'mem', 'kind', 'op', 'cmd', 'count']
        
    def _extract_balanced_parens(self, line, start_pos):
        """Extract content between balanced parentheses starting at start_pos."""
        if start_pos >= len(line) or line[start_pos] != '(':
            return ''
        
        depth = 0
        content = ''
        for i in range(start_pos, len(line)):
            c = line[i]
            if c == '(':
                depth += 1
            elif c == ')':
                depth -= 1
                if depth == 0:
                    return content  # Return content without the outer parens
            if depth > 0 and i > start_pos:  # Skip the opening paren
                content += c
        
        return content  # Incomplete - return what we have
    
    def _parse_params(self, params_str):
        """Parse LLVM IR parameter string into list of (type, name) tuples."""
        params = []
        if not params_str or params_str.strip() == '':
            return params
        
        # Split by comma, handling nested types like %struct.foo*, [10 x i8], etc.
        depth = 0
        current = ''
        parts = []
        for c in params_str:
            if c == '(' or c == '<' or c == '{' or c == '[':
                depth += 1
            elif c == ')' or c == '>' or c == '}' or c == ']':
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
            
            # Skip LLVM metadata and varargs
            if part.startswith('metadata') or part == '...':
                continue
            
            # Handle attributes like nocapture, readonly, noundef, etc.
            # Also handle sret(%struct.foo), align N, dereferenceable(N), etc.
            tokens = part.split()
            
            # Find the %name token (parameter name)
            param_name = None
            param_type_parts = []
            
            for i, token in enumerate(tokens):
                # Skip LLVM attributes
                if token in ['nocapture', 'readonly', 'writeonly', 'noundef', 
                             'nonnull', 'inreg', 'zeroext', 'signext', 'byval',
                             'sret', 'noalias', 'nocallback', 'nounwind', 'willreturn',
                             'memory', 'argmemonly']:
                    continue
                # Skip attributes with parentheses like sret(%struct.foo), byval(%struct.foo)
                if '(' in token and not token.startswith('%'):
                    continue
                # Skip align N, dereferenceable(N)
                if token in ['align', 'dereferenceable', 'dereferenceable_or_null']:
                    break  # Rest is alignment info
                if token.startswith('%') and (
                    token.startswith('%struct.') or
                    token.startswith('%union.') or
                    token.startswith('%class.') or
                    token.startswith('%"')
                ):
                    # Named LLVM type references — these are types, not param names
                    param_type_parts.append(token)
                elif token.startswith('%'):
                    param_name = token[1:]  # Remove %
                    break
                else:
                    param_type_parts.append(token)
            
            if param_type_parts and param_name:
                param_type = ' '.join(param_type_parts)
                params.append((param_type, param_name))
            elif param_name:
                # Type might be empty (uncommon but possible)
                pass
            elif param_type_parts:
                # No %name token — e.g. unnamed/numbered IR params.
                # Assign a positional name so downstream analysis still works.
                param_type = ' '.join(param_type_parts)
                params.append((param_type, 'param_' + str(len(params))))
        
        return params

    def _split_call_arguments(self, args_str):
        """Split LLVM IR call arguments while respecting nested delimiters."""
        if not args_str:
            return []
        parts = []
        current = ''
        depth = 0
        for char in args_str:
            if char in '([{<':
                depth += 1
            elif char in ')]}>':
                depth = max(0, depth - 1)
            elif char == ',' and depth == 0:
                if current.strip():
                    parts.append(current.strip())
                current = ''
                continue
            current += char
        if current.strip():
            parts.append(current.strip())
        return parts

    def _extract_arg_register(self, arg_text):
        """Return the SSA register referenced by a call argument if present."""
        if not arg_text:
            return None
        match = re.search(r'%([A-Za-z0-9_.]+)', arg_text)
        if match:
            return match.group(1)
        return None
    
    def _is_data_pointer_type(self, type_str):
        """Check if a type string represents a data pointer (not struct/function pointer)."""
        if not type_str:
            return False
        # Data pointers: i8*, char*, void*, i8* nocapture, ptr (opaque), etc.
        # Not data pointers: %struct.XXX*, %class.XXX*, i32 (...)*
        type_lower = type_str.lower().strip()
        
        # Check for struct/class pointer (internal types)
        if '%struct' in type_str or '%class' in type_str or '%union' in type_str:
            return False
        
        # Check for function pointer
        if '...' in type_str:
            return False
        
        # LLVM opaque pointer mode (LLVM 15+): bare 'ptr' is a generic pointer
        if type_lower == 'ptr':
            return True
        
        # Check for data pointer patterns
        data_ptr_patterns = [
            'i8*', 'char*', 'void*', 'uint8_t*', 'int8_t*',
            'i16*', 'i32*', 'i64*', 'short*', 'int*', 'long*',
            'float*', 'double*',
            '* nocapture', '* readonly'
        ]
        for pattern in data_ptr_patterns:
            if pattern in type_lower or type_lower.startswith(pattern.replace('*', '')):
                return True
        
        # Generic: if it ends with * and doesn't contain struct/class, treat as data
        if type_str.rstrip().endswith('*'):
            # Check it's not a function pointer or struct
            if '%struct' not in type_str and '%class' not in type_str and '(...)' not in type_str:
                return True
        
        return False
    
    def get_data_params(self, func_name):
        """Get indices of parameters that are likely data pointers."""
        params = self.func_params.get(func_name, [])
        data_param_indices = []
        for i, (ptype, pname) in enumerate(params):
            if self._is_data_pointer_type(ptype):
                # Exclude: parser, ctx, context, handle, state (internal structs)
                # Covers both C naming (ctx, state) and C++ (this, self, instance)
                pname_lower = pname.lower()
                exclude_names = ['parser', 'ctx', 'context', 'handle', 'state', 
                                 'self', 'this', 'instance', 'userdata',
                                 'allocator', 'deleter', 'traits']
                if not any(ex in pname_lower for ex in exclude_names):
                    data_param_indices.append(i)
        return data_param_indices

    def get_control_params(self, func_name):
        """Get indices of parameters that look like narrow control knobs."""
        params = self.func_params.get(func_name, [])
        control_param_indices = []
        for i, (ptype, pname) in enumerate(params):
            pname_lower = pname.lower()
            if any(keyword in pname_lower for keyword in self.control_param_keywords):
                control_param_indices.append(i)
        return control_param_indices

    def _resolve_reg_to_param(self, func, reg, caller_name_to_index, depth=0):
        """Resolve a register to a caller parameter index, following GEP chains.

        Returns the caller parameter index if *reg* (or a GEP base of *reg*)
        matches a caller parameter, else ``None``.  Follows up to 2 levels of
        GEP indirection (e.g. ``param->field`` and ``param->sub->field``).
        """
        if reg in caller_name_to_index:
            return caller_name_to_index[reg]
        if depth >= 2:
            return None
        base_key = self.gep_base.get((func, reg))
        if base_key is None:
            return None
        _, base_reg = base_key
        return self._resolve_reg_to_param(func, base_reg, caller_name_to_index, depth + 1)

    def get_edge_param_flow(self, caller, callee):
        """Map caller parameter indices to callee parameter indices using recorded call sites.

        Extends plain SSA-register identity with GEP tracing so that
        arguments derived from ``getelementptr`` on a caller parameter (the
        common ``param->field`` pattern) are still counted as forwarded.
        """
        key = (caller, callee)
        if key in self.call_args and self.call_args[key]:
            return self.call_args[key]

        caller_params = self.func_params.get(caller, [])
        callee_params = self.func_params.get(callee, [])
        if not caller_params or not callee_params:
            return []

        caller_name_to_index = {}
        for index, param in enumerate(caller_params):
            caller_name_to_index[param[1]] = index

        flows = []
        seen = set()
        for arg_list in self.call_sites.get(key, []):
            for callee_index, arg_text in enumerate(arg_list[:len(callee_params)]):
                reg = self._extract_arg_register(arg_text)
                if not reg:
                    continue
                param_idx = self._resolve_reg_to_param(caller, reg, caller_name_to_index)
                if param_idx is not None:
                    mapping = (param_idx, callee_index)
                    if mapping not in seen:
                        seen.add(mapping)
                        flows.append(mapping)

        if flows:
            self.call_args[key] = flows
        return flows
    
    def parse_ll_file(self, ll_path: str):
        """Parse a single LLVM IR file."""
        if not os.path.exists(ll_path):
            return
        
        with open(ll_path, 'r') as f:
            content = f.read()
        
        lines = content.split('\n')
        current_func = None
        
        # ---- Parse vtable globals (@_ZTV*) for C++ virtual dispatch ----
        # Vtable constants look like:
        #   @_ZTV4Base = ... constant { [4 x ptr] } { [4 x ptr] [ptr null, ptr @_ZTI4Base, ptr @_ZN4Base3fooEv, ptr @_ZN4Base3barEv] }, ...
        # We extract function names from each slot position.
        vtable_pattern = re.compile(
            r'^@(_ZTV[a-zA-Z0-9_]+)\s*=.*?(?:constant|global)\s+.*?\{.*?\[.*?\]\s*\[([^\]]+)\]'
        )
        for line in lines:
            m = vtable_pattern.match(line)
            if not m:
                continue
            vtable_name = m.group(1)
            entries_str = m.group(2)
            # Parse slot entries: "ptr null, ptr @_ZTI4Base, ptr @_ZN4Base3fooEv, ..."
            slot_entries = []
            for entry in entries_str.split(','):
                entry = entry.strip()
                func_match = re.search(r'@([a-zA-Z_][a-zA-Z0-9_]*)', entry)
                if func_match:
                    fname = func_match.group(1)
                    # Skip typeinfo and typeinfo-name entries
                    if fname.startswith('_ZTI') or fname.startswith('_ZTS'):
                        slot_entries.append(None)
                    else:
                        slot_entries.append(fname)
                else:
                    slot_entries.append(None)  # null or non-function entry
            if slot_entries:
                self.vtable_entries[vtable_name] = slot_entries
                print("DEBUG LLVM: Parsed vtable @" + vtable_name + " with " + str(len(slot_entries)) + " slots")
        
        # Join continuation lines for function definitions
        # LLVM IR function definitions can span multiple lines
        i = 0
        while i < len(lines):
            line_num = i + 1
            line = lines[i]
            
            # Check for function definition start - might need to join lines
            if self.func_def_pattern.match(line) and '{' not in line:
                # Function definition continues on next line(s)
                # Join lines until we find '{'
                joined_line = line
                while i + 1 < len(lines) and '{' not in joined_line:
                    i += 1
                    joined_line += ' ' + lines[i].strip()
                line = joined_line
            
            # Check for function declaration - might also span lines  
            if self.func_decl_pattern.match(line) and not line.strip().endswith(')'):
                joined_line = line
                while i + 1 < len(lines) and ')' not in joined_line.split('//')[0]:
                    i += 1
                    joined_line += ' ' + lines[i].strip()
                line = joined_line
            
            location = str(ll_path) + ":" + str(line_num)
            
            # Function definition - extract params by finding balanced parens
            match = self.func_def_pattern.match(line)
            if match:
                func_name = match.group(1)
                current_func = func_name
                
                # Extract parameter string by finding balanced parentheses
                paren_start = line.find('(')
                if paren_start != -1:
                    params_str = self._extract_balanced_parens(line, paren_start)
                else:
                    params_str = ''
                
                params = self._parse_params(params_str)
                self.functions[func_name] = {'defined': True, 'location': location, 'params': params}
                self.func_params[func_name] = params
                i += 1
                continue
            
            # Function declaration
            match = self.func_decl_pattern.match(line)
            if match:
                func_name = match.group(1)
                
                # Extract parameter string by finding balanced parentheses
                paren_start = line.find('(')
                if paren_start != -1:
                    params_str = self._extract_balanced_parens(line, paren_start)
                else:
                    params_str = ''
                
                params = self._parse_params(params_str)
                if func_name not in self.functions:
                    self.functions[func_name] = {'defined': False, 'location': location, 'params': params}
                    self.func_params[func_name] = params
                i += 1
                continue
            
            # End of function
            if line.strip() == '}':
                current_func = None
                i += 1
                continue
            
            if current_func is None:
                i += 1
                continue
            
            # Direct call
            for match in self.direct_call_pattern.finditer(line):
                callee = match.group(1)
                args_str = match.group(2)
                # Skip LLVM intrinsics
                if not callee.startswith('llvm.'):
                    self.adjacency[current_func].add(callee)
                    self.call_sites[(current_func, callee)].append(self._split_call_arguments(args_str))
            
            # Indirect call through function pointer
            for match in self.indirect_call_pattern.finditer(line):
                ptr_name = match.group(1)
                self.indirect_calls.append((current_func, ptr_name, location))
            
            # Store of function address to pointer (address-taken)
            for match in self.store_pattern.finditer(line):
                func_name = match.group(1)
                ptr_name = match.group(2)
                # Skip LLVM intrinsics
                if not func_name.startswith('llvm.'):
                    self.address_taken[func_name].append(location)
                    self.func_ptr_stores.append((ptr_name, func_name, location, current_func))
                    self.pointer_targets[(current_func, ptr_name)].add(func_name)
            
            # Store of pointer to pointer (propagation)
            for match in self.store_ptr_pattern.finditer(line):
                src_ptr = match.group(1)
                dst_ptr = match.group(2)
                # Skip if regex accidentally captured a struct type name
                if src_ptr.startswith(('struct.', 'class.', 'union.')):
                    continue
                if dst_ptr.startswith(('struct.', 'class.', 'union.')):
                    continue
                # Will resolve after all stores are collected
                self.func_ptr_stores.append((dst_ptr, src_ptr, location, current_func))
            
            # Load instruction: %dst = load ... %src  OR  %dst = load ... @global
            # This loads a function pointer from memory into a register
            for match in self.load_pattern.finditer(line):
                dst_reg = match.group(1)
                src_mem = match.group(2)
                self.func_ptr_loads.append((dst_reg, src_mem, location))
                # Also add to stores for propagation (dst <- src)
                self.func_ptr_stores.append((dst_reg, src_mem, location, current_func))
            
            # Special handling for loads from global variables (@name).
            # If the global IS a known function name, record a direct
            # pointer_target so resolution doesn't depend on seeing a
            # prior store to the global.
            for match in self.load_global_pattern.finditer(line):
                dst_reg = match.group(1)
                global_name = match.group(2)
                if global_name in self.functions:
                    self.pointer_targets[(current_func, dst_reg)].add(global_name)
            
            # Track GEP instructions for struct-field indirect call resolution.
            # When a function pointer is stored via GEP into a struct field in
            # one function and loaded via GEP from the same struct field in
            # another function, the SSA-scoped pointer_targets cannot connect
            # them.  gep_info bridges this gap by recording which registers
            # correspond to which (struct_type, field_index).
            for match in self.gep_pattern.finditer(line):
                dst_reg = match.group(1)
                struct_type = match.group(2)
                base_reg = match.group(3)
                field_idx = int(match.group(4))
                self.gep_info[(current_func, dst_reg)] = (struct_type, field_idx)
                # Record base register for nested GEP chaining
                self.gep_base[(current_func, dst_reg)] = (current_func, base_reg)
            
            # Track vtable-style GEP (bare-pointer indexing without struct type).
            # Pattern: %vfn = getelementptr inbounds ptr, ptr %vtable, i64 2
            # This produces a pointer to the vtable slot at the given index.
            for match in self.vtable_gep_pattern.finditer(line):
                dst_reg = match.group(1)
                base_reg = match.group(2)
                slot_idx = int(match.group(3))
                self.vtable_slot_info[(current_func, dst_reg)] = (base_reg, slot_idx)
            
            i += 1  # Move to next line
    
    def resolve_function_pointers(self):
        """KELP: Resolve indirect calls using pointer analysis."""
        # Pre-pass: bridge struct-field function pointer stores and loads
        # across different functions.  When @func is stored into a struct
        # field via GEP in function A, and another function B loads from
        # the same struct field via GEP, propagate the targets.

        # Step 1: collect function names stored into each struct field.
        for dst_ptr, src_ptr, loc, owner in self.func_ptr_stores:
            if src_ptr not in self.functions:
                continue
            gep_key = (owner, dst_ptr)
            if gep_key not in self.gep_info:
                continue
            struct_type, field_idx = self.gep_info[gep_key]
            self.struct_field_targets[(struct_type, field_idx)].add(src_ptr)

        # Step 2: for every load whose source register is a GEP to a
        # struct field that has known targets, seed pointer_targets for
        # the destination register.
        for dst_ptr, src_ptr, loc, owner in self.func_ptr_stores:
            src_gep_key = (owner, src_ptr)
            if src_gep_key not in self.gep_info:
                continue
            field_key = self.gep_info[src_gep_key]
            targets = self.struct_field_targets.get(field_key)
            if not targets:
                continue
            dst_key = (owner, dst_ptr)
            old_size = len(self.pointer_targets[dst_key])
            self.pointer_targets[dst_key].update(targets)
            if len(self.pointer_targets[dst_key]) > old_size:
                print("DEBUG LLVM: Struct-field bridge: seeded (" + str(owner) + ", " + str(dst_ptr) + ") from " + str(field_key) + " -> " + str(targets))

        # Step 2b: Nested GEP chaining.
        # When %A = GEP %struct.Ctx, %ctx, 0, 3   (gep_info -> (Ctx, 3))
        # and  %B = GEP %struct.Handlers, %A, 0, 2 (gep_info -> (Handlers, 2))
        # then struct_field_targets for (Handlers, 2) should propagate through
        # the chain to any load from %B.  We achieve this by seeding
        # struct_field_targets from inner-level GEPs whose base register is
        # itself a GEP result, then re-running the Step 2 bridge.
        chained_any = False
        for (func, dst_reg), (struct_type, field_idx) in list(self.gep_info.items()):
            base_key = self.gep_base.get((func, dst_reg))
            if not base_key or base_key not in self.gep_info:
                continue
            # dst_reg is a nested GEP whose base is also a GEP result.
            # The inner field (struct_type, field_idx) is reachable through
            # the outer struct.  Propagate any known targets into the
            # pointer_targets for dst_reg so downstream loads can resolve.
            inner_targets = self.struct_field_targets.get((struct_type, field_idx))
            if inner_targets:
                dst_key = (func, dst_reg)
                old_size = len(self.pointer_targets[dst_key])
                self.pointer_targets[dst_key].update(inner_targets)
                if len(self.pointer_targets[dst_key]) > old_size:
                    chained_any = True
                    print("DEBUG LLVM: Nested GEP chain: seeded (" + str(func) + ", " + str(dst_reg) + ") via " + str((struct_type, field_idx)) + " -> " + str(inner_targets))

        # Re-run Step 2 bridge if chaining produced new targets so loads
        # from nested GEP registers pick them up.
        if chained_any:
            for dst_ptr, src_ptr, loc, owner in self.func_ptr_stores:
                src_gep_key = (owner, src_ptr)
                if src_gep_key not in self.gep_info:
                    continue
                field_key = self.gep_info[src_gep_key]
                targets = self.struct_field_targets.get(field_key)
                if not targets:
                    continue
                dst_key = (owner, dst_ptr)
                old_size = len(self.pointer_targets[dst_key])
                self.pointer_targets[dst_key].update(targets)

        # Iterate to propagate pointer targets (flow-insensitive, but works for most cases)
        changed = True
        iterations = 0
        max_iterations = 10
        
        while changed and iterations < max_iterations:
            changed = False
            iterations += 1
            
            for dst_ptr, src_ptr, loc, owner in self.func_ptr_stores:
                key = (owner, dst_ptr)
                # If src_ptr is a function name (not a pointer), it's already handled
                if src_ptr in self.functions:
                    old_size = len(self.pointer_targets[key])
                    self.pointer_targets[key].add(src_ptr)
                    if len(self.pointer_targets[key]) > old_size:
                        changed = True
                # If src_ptr is a pointer, propagate its targets (same function scope)
                else:
                    src_key = (owner, src_ptr)
                    if src_key in self.pointer_targets:
                        old_size = len(self.pointer_targets[key])
                        self.pointer_targets[key].update(self.pointer_targets[src_key])
                        if len(self.pointer_targets[key]) > old_size:
                            changed = True
        
        # ---- Vtable resolution ----
        # Resolve the load-vptr → GEP-vtable → load-fptr → call/invoke pattern.
        # For each vtable GEP slot info (func, dst_reg) -> (base_reg, slot_idx),
        # trace the base_reg back to a load from a global @_ZTV* vtable.
        # If found, seed pointer_targets for the register that loaded from
        # the GEP result (i.e. the function pointer).
        vtable_resolved = 0
        for (func, gep_dst), (base_reg, slot_idx) in self.vtable_slot_info.items():
            # The base_reg should have been loaded from a vtable global.
            # Check if we have pointer_targets for (func, base_reg) that
            # correspond to vtable globals, or check load records.
            # In practice, the base_reg comes from:
            #   %vtable = load ptr, ptr %obj  (loads vptr from object)
            # and there's an earlier store of @_ZTV... + offset to the object.
            # We check all known vtable globals for a matching slot.

            # Find what loads from this GEP result (i.e. who loads the fptr)
            for dst_ptr, src_ptr, loc, owner in self.func_ptr_stores:
                if owner != func or src_ptr != gep_dst:
                    continue
                # dst_ptr is the register that holds the loaded function pointer.
                # Try all vtables — the slot_idx selects the virtual method.
                for vtable_name, slots in self.vtable_entries.items():
                    if slot_idx < len(slots) and slots[slot_idx] is not None:
                        target = slots[slot_idx]
                        if target in self.functions or not target.startswith('_ZTI'):
                            key = (func, dst_ptr)
                            old_size = len(self.pointer_targets[key])
                            self.pointer_targets[key].add(target)
                            if len(self.pointer_targets[key]) > old_size:
                                vtable_resolved += 1
                                print("DEBUG LLVM: Vtable resolution: (" + str(func) + ", " + str(dst_ptr) + ") -> " + str(target) + " via @" + str(vtable_name) + "[" + str(slot_idx) + "]")
        
        if vtable_resolved:
            print("DEBUG LLVM: Resolved " + str(vtable_resolved) + " vtable dispatch targets")
        
        # Now resolve indirect calls.
        # Struct-field dispatch (e.g. expat's m_processor) can legitimately
        # have 15-20+ targets; allow up to max_targets_per_call before
        # considering imprecise.
        for caller, ptr_name, location in self.indirect_calls:
            targets = self.pointer_targets.get((caller, ptr_name), set())
            if targets:
                if len(targets) > self.max_targets_per_call:
                    print("DEBUG LLVM: Skipping over-resolved indirect call in " + str(caller) + " via '" + str(ptr_name) + "' (" + str(len(targets)) + " targets, likely imprecise)")
                    continue
                for target in targets:
                    self.adjacency[caller].add(target)
                    print("DEBUG LLVM: Resolved indirect call in " + str(caller) + " via '" + str(ptr_name) + "' -> " + str(target))
            else:
                print("DEBUG LLVM: Could not resolve indirect call in " + str(caller) + " via '" + str(ptr_name) + "'")
    
    def build_callgraph(self, ll_files: List[str]) -> Tuple[Dict, Dict, Dict]:
        """
        Build callgraph from LLVM IR files.
        Returns:
            adjacency: caller -> [callees]
            usr_to_file: function -> location (simulated USR)
            usr_to_name: function -> name
        """
        print("DEBUG LLVM: Parsing " + str(len(ll_files)) + " LLVM IR files...")
        
        for ll_file in ll_files:
            self.parse_ll_file(ll_file)
        
        print("DEBUG LLVM: Found " + str(len(self.functions)) + " functions")
        print("DEBUG LLVM: Found " + str(sum(len(v) for v in self.adjacency.values())) + " direct calls")
        print("DEBUG LLVM: Found " + str(len(self.indirect_calls)) + " indirect calls")
        print("DEBUG LLVM: Found " + str(len(self.address_taken)) + " address-taken functions")
        
        # Resolve function pointers
        self.resolve_function_pointers()
        
        # Convert to expected format
        adjacency = {caller: list(callees) for caller, callees in self.adjacency.items()}
        usr_to_file = {name: info.get('location', '') for name, info in self.functions.items()}
        usr_to_name = {name: name for name in self.functions}
        
        return adjacency, usr_to_file, usr_to_name
    
    def score_path(self, path):
        """
        Score a call path by parameter-propagation potential.
        Higher score = better path (more likely to pass external data to sink).

        Evaluates the *entry point* (path[0]) for data/control parameters
        and naming signals, then traces parameter forwarding along each
        call edge to estimate how much fuzzer-controlled data survives to
        the sink.

        The caller is responsible for pre-filtering paths to public API
        entry points before scoring; this function only ranks viable
        candidates on data-flow merit.

        Args:
            path: list of function names [entry, ..., sink].
        """
        if not path or len(path) < 1:
            return -1000
        
        score = 0
        
        # The entry point (first function in path)
        entry = path[0]
        entry_data_params = self.get_data_params(entry)
        entry_control_params = self.get_control_params(entry)
        
        # Big bonus for entry points that accept data pointers
        if entry_data_params:
            score += 10 * len(entry_data_params)
        if entry_control_params:
            score += 4 * min(2, len(entry_control_params))
        
        # Penalty for cleanup functions (C and C++ patterns)
        entry_lower = entry.lower()
        # Strip C++ namespace/class qualifiers for name matching
        entry_basename = entry_lower.rsplit('::', 1)[-1] if '::' in entry_lower else entry_lower
        if any(kw in entry_basename for kw in ('free', 'destroy', 'cleanup', 'release',
                                                 'deallocate', 'dispose')):
            score -= 15
        if any(kw in entry_basename for kw in ('reset', 'close', 'shutdown', 'finalize')):
            score -= 10
        # C++ destructors (mangled names contain 'D0', 'D1', 'D2' or ~ClassName)
        if entry_basename.startswith('~') or '::~' in entry_lower:
            score -= 15
        
        # Bonus for data-processing functions (C and C++ patterns)
        if any(kw in entry_basename for kw in ('parse', 'process', 'decode', 'deserialize',
                                                 'unmarshal', 'from_', 'load')):
            score += 8
        if any(kw in entry_basename for kw in ('handle', 'run', 'execute', 'dispatch',
                                                 'invoke', 'apply', 'transform')):
            score += 5
        # C++ iterator/container methods are poor entry points
        if entry_basename in ('begin', 'end', 'cbegin', 'cend', 'rbegin', 'rend',
                              'size', 'empty', 'clear', 'swap', 'at', 'front', 'back',
                              'push_back', 'pop_back', 'emplace_back', 'insert', 'erase',
                              'emplace', 'resize', 'reserve', 'capacity'):
            score -= 8
        # C++ operator overloads are poor entry points
        if entry_basename.startswith('operator'):
            score -= 8
        
        # SMALL penalty for each hop (prefer shorter paths, but not as much as data flow)
        score -= len(path) - 1

        # Trace caller→callee parameter propagation along the path.
        tracked_params = set(entry_data_params + entry_control_params)
        for index in range(len(path) - 1):
            caller = path[index]
            callee = path[index + 1]
            edge_flow = self.get_edge_param_flow(caller, callee)
            if not edge_flow:
                score -= 2
                tracked_params = set()
                continue

            next_tracked = set()
            propagated = 0
            for caller_param_idx, callee_param_idx in edge_flow:
                if caller_param_idx in tracked_params:
                    next_tracked.add(callee_param_idx)
                    propagated += 1

            if propagated:
                score += 8 * propagated
                tracked_params = next_tracked
            else:
                score -= 1
                tracked_params = next_tracked

        # Extra bonus if entry-controlled parameters survive to the sink.
        if tracked_params:
            score += 6 * len(tracked_params)
        
        return score

    # Keep old name as alias for backward compatibility.
    def score_path_taint(self, path):
        return self.score_path(path)

    def trace_parameter_flow(self, path):
        """Trace data flow from entry to sink along *path*.

        Returns a dict with:
          entry_params            – [(type, name), …] for the entry function
          sink_params             – [(type, name), …] for the sink function
          entry_controlled_at_sink – {sink_param_idx: (entry_param_idx, entry_param_name)}
          sink_internal_params    – [name, …] for sink params with NO entry source
        """
        if not path or len(path) < 2:
            return {}

        entry_func = path[0]
        sink_func = path[-1]
        entry_params = self.func_params.get(entry_func, [])
        sink_params = self.func_params.get(sink_func, [])

        if not entry_params or not sink_params:
            return {}

        # Start with entry data + control param indices as tainted.
        entry_data = self.get_data_params(entry_func)
        entry_ctrl = self.get_control_params(entry_func)
        tainted = set(entry_data + entry_ctrl)

        if not tainted:
            # Nothing flows in — every sink param is internal.
            return {
                'entry_params': list(entry_params),
                'sink_params': list(sink_params),
                'entry_controlled_at_sink': {},
                'sink_internal_params': [p[1] for p in sink_params],
            }

        # Keep a mapping tainted_param_idx → originating entry_param_idx
        # so we can report which entry param reaches which sink param.
        origin = {idx: idx for idx in tainted}

        for hop in range(len(path) - 1):
            caller = path[hop]
            callee = path[hop + 1]
            edge_flow = self.get_edge_param_flow(caller, callee)
            if not edge_flow:
                # Flow unknown at this hop — conservatively lose all taint.
                tainted = set()
                origin = {}
                break

            next_tainted = set()
            next_origin = {}
            for caller_idx, callee_idx in edge_flow:
                if caller_idx in tainted:
                    next_tainted.add(callee_idx)
                    next_origin[callee_idx] = origin[caller_idx]

            tainted = next_tainted
            origin = next_origin

        # Build result
        controlled = {}
        for sink_idx, entry_idx in origin.items():
            if sink_idx < len(sink_params):
                controlled[sink_idx] = (entry_idx,
                                        entry_params[entry_idx][1] if entry_idx < len(entry_params) else '?')

        internal = []
        for i, (_, pname) in enumerate(sink_params):
            if i not in controlled:
                internal.append(pname)

        return {
            'entry_params': list(entry_params),
            'sink_params': list(sink_params),
            'entry_controlled_at_sink': controlled,
            'sink_internal_params': internal,
        }


def find_ll_files(root_dir: str) -> List[str]:
    """Find all .ll files under root directory."""
    ll_files = []
    for root, dirs, files in os.walk(root_dir):
        for f in files:
            if f.endswith('.ll'):
                ll_files.append(os.path.join(root, f))
    return ll_files


# Global builder instance for access from harness_plan
_builder_instance = None

def build_callgraph_from_build_log(log_path: str, root_dir: str) -> Tuple[Dict, Dict, Dict]:
    """
    Build callgraph from build log and LLVM IR files.
    """
    global _builder_instance
    
    # Find LLVM IR files
    ll_files = find_ll_files(root_dir)
    
    # Also check for ll_file entries in build log
    if os.path.exists(log_path):
        with open(log_path, 'r') as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    if 'll_file' in entry:
                        ll_path = entry['ll_file']
                        if os.path.exists(ll_path) and ll_path not in ll_files:
                            ll_files.append(ll_path)
                except:
                    continue
    
    _builder_instance = LLVMCallGraphBuilder()
    result = _builder_instance.build_callgraph(ll_files)
    
    # Fallback: Extract function signatures from header files for missing params
    _fill_missing_params_from_headers(log_path, root_dir)
    
    return result


def _fill_missing_params_from_headers(log_path: str, root_dir: str):
    """
    Fill in missing function parameters from header files using libclang.
    """
    global _builder_instance
    
    if _builder_instance is None:
        return
    
    # Find functions in callgraph but missing params OR with empty params
    all_callgraph_funcs = set(_builder_instance.adjacency.keys())
    for callees in _builder_instance.adjacency.values():
        all_callgraph_funcs.update(callees)
    
    # Include functions with empty params too (not just missing)
    missing_params = [f for f in all_callgraph_funcs 
                      if f not in _builder_instance.func_params 
                      or not _builder_instance.func_params.get(f)]
    
    if not missing_params:
        return
    
    print("DEBUG LLVM: Trying to extract params from headers for " + str(len(missing_params)) + " functions...")
    
    # Use public_api to extract signatures from headers
    try:
        from public_api import load_compile_commands, find_public_include_dirs, extract_function_signatures
        
        cmds = load_compile_commands(log_path)
        include_dirs = find_public_include_dirs(cmds, root_dir)
        signatures = extract_function_signatures(include_dirs)
        
        filled = 0
        for func_name in missing_params:
            if func_name in signatures:
                _builder_instance.func_params[func_name] = signatures[func_name]
                print("DEBUG LLVM: Filled params for " + func_name + " from header: " + str(signatures[func_name][:2]))
                filled += 1
        
        print("DEBUG LLVM: Filled params for " + str(filled) + " functions from headers")
    except Exception as e:
        print("DEBUG LLVM: Failed to extract from headers: " + str(e))

    # Second pass: extract params from .c source files for functions still missing.
    still_missing = [f for f in all_callgraph_funcs
                     if f not in _builder_instance.func_params
                     or not _builder_instance.func_params.get(f)]
    if still_missing:
        _fill_params_from_source(still_missing, root_dir)


def _resolve_ll_to_source_path(ll_path: str, root_dir: str) -> str:
    """Resolve an .ll file path to the corresponding .c/.cpp source, simple glob."""
    import glob as _glob
    p = ll_path.split(':')[0] if ':' in ll_path else ll_path
    if not p.endswith('.ll'):
        return p
    base = os.path.splitext(os.path.basename(p))[0]
    for ext in ('*.c', '*.cc', '*.cpp', '*.cxx'):
        for src in _glob.glob(os.path.join(root_dir, '**', ext), recursive=True):
            if os.path.splitext(os.path.basename(src))[0] == base:
                return src
    return ''


def _fill_params_from_source(func_names, root_dir):
    """Fill func_params for internal functions by parsing their .c source files."""
    global _builder_instance
    if _builder_instance is None:
        return

    try:
        from vuln_analyzer import extract_function_parameters, extract_function_source
        from pathlib import Path
    except ImportError:
        return

    # Group functions by source file to avoid re-reading the same file
    file_funcs = {}  # source_path -> [func_name, ...]
    for func_name in func_names:
        info = _builder_instance.functions.get(func_name, {})
        loc = info.get('location', '')
        if not loc:
            continue
        src = _resolve_ll_to_source_path(loc, root_dir)
        if src and os.path.exists(src):
            file_funcs.setdefault(src, []).append(func_name)

    filled = 0
    for src_path, funcs in file_funcs.items():
        try:
            content = open(src_path, 'r', encoding='utf-8', errors='ignore').read()
        except Exception:
            continue
        for func_name in funcs:
            params_list = extract_function_parameters(content, func_name)
            if params_list:
                # Convert [{'name': ..., 'type': ...}] → [(type, name)]
                tuples = [(p.get('type', 'unknown'), p['name']) for p in params_list if p.get('name')]
                if tuples:
                    _builder_instance.func_params[func_name] = tuples
                    filled += 1

    if filled:
        print("DEBUG LLVM: Filled params for " + str(filled) + " functions from .c source")

def score_path_taint(path):
    """
    Score a path using the global builder instance.
    Higher score = better path for fuzzing.
    """
    global _builder_instance
    if _builder_instance is None:
        # Return a default score if no builder
        return -len(path) if path else -1000
    return _builder_instance.score_path(path)

def get_func_params(func_name):
    """Get parameters for a function."""
    global _builder_instance
    if _builder_instance is None:
        return []
    return _builder_instance.func_params.get(func_name, [])

def get_data_params(func_name):
    """Get data parameter indices for a function."""
    global _builder_instance
    if _builder_instance is None:
        return []
    return _builder_instance.get_data_params(func_name)


def trace_parameter_flow(path):
    """Trace entry→sink parameter flow using the global builder instance."""
    global _builder_instance
    if _builder_instance is None:
        return {}
    return _builder_instance.trace_parameter_flow(path)


def find_public_wrapper(adjacency, usr_to_file, sink_name, public_names):
    """
    Reverse-BFS from sink to find nearest public API.
    Returns path [public, ..., sink].
    """
    from collections import deque
    
    if sink_name not in adjacency and sink_name not in {v for callees in adjacency.values() for v in callees}:
        return None
    
    # Find callers of sink
    queue = deque()
    visited = {sink_name}
    
    for caller, callees in adjacency.items():
        if sink_name in callees and caller not in visited:
            visited.add(caller)
            queue.append([sink_name, caller])
    
    while queue:
        path = queue.popleft()
        cur = path[-1]
        if cur in public_names:
            return path
        for caller, callees in adjacency.items():
            if cur in callees and caller not in visited:
                visited.add(caller)
                queue.append(path + [caller])
    
    return None


if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser(description='Build callgraph from LLVM IR')
    p.add_argument('--root', required=True, help='Root directory to search for .ll files')
    p.add_argument('--log', help='Build log with ll_file entries')
    args = p.parse_args()
    
    if args.log:
        adj, usr_to_file, usr_to_name = build_callgraph_from_build_log(args.log, args.root)
    else:
        ll_files = find_ll_files(args.root)
        builder = LLVMCallGraphBuilder()
        adj, usr_to_file, usr_to_name = builder.build_callgraph(ll_files)
    
    print(json.dumps({'adjacency': adj, 'usr_to_file': usr_to_file}, indent=2))