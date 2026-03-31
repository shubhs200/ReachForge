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
    4. Track parameter types for taint analysis
    """
    
    def __init__(self):
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
        
        # Parameter flow tracking for taint analysis
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
        self.direct_call_pattern = re.compile(r'call\s+[^@]*@([a-zA-Z_][a-zA-Z0-9_]*)\s*\(([^)]*)\)')
        # Indirect calls in LLVM IR look like: call i32 %5(i8* %6) or call i32 %funcptr(...)
        # Match both numbered (%5) and named (%funcptr) locals
        self.indirect_call_pattern = re.compile(r'call\s+[^@]*?%([a-zA-Z0-9_.]+)\s*\(')
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
        # Captures: dst_register, struct_type, field_index
        # Example: %6 = getelementptr inbounds %struct.XML_ParserStruct, %struct.XML_ParserStruct* %5, i32 0, i32 45
        self.gep_pattern = re.compile(
            r'%([a-zA-Z0-9_.]+)\s*=\s*getelementptr\s+(?:inbounds\s+)?'
            r'(%(?:struct|class|union)\.[a-zA-Z0-9_.]+)\s*,'
            r'.*?(?:i32|i64)\s+0\s*,\s*(?:i32|i64)\s+(\d+)'
        )
        # Maps (owning_func, register) -> (struct_type, field_index)
        self.gep_info = {}
        # Maps (struct_type, field_index) -> {function_names stored into that field}
        self.struct_field_targets = defaultdict(set)
        
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
        
        # Debug: show what we're trying to parse
        if len(params_str) < 200:
            print("DEBUG LLVM _parse_params: '" + str(params_str[:100]) + "'")
        
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
                if token.startswith('%'):
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
        # Data pointers: i8*, char*, void*, i8* nocapture, etc.
        # Not data pointers: %struct.XXX*, %class.XXX*, i32 (...)*
        type_lower = type_str.lower()
        
        # Check for struct/class pointer (internal types)
        if '%struct' in type_str or '%class' in type_str or '%union' in type_str:
            return False
        
        # Check for function pointer
        if '...' in type_str:
            return False
        
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
                # Additional heuristics: buffer parameters often have names like:
                # data, buf, buffer, input, s, ptr, p
                # Exclude: parser, ctx, context, handle, state (internal structs)
                pname_lower = pname.lower()
                exclude_names = ['parser', 'ctx', 'context', 'handle', 'state', 
                                 'self', 'this', 'instance', 'userdata']
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

    def get_edge_param_flow(self, caller, callee):
        """Map caller parameter indices to callee parameter indices using recorded call sites."""
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
                if reg and reg in caller_name_to_index:
                    mapping = (caller_name_to_index[reg], callee_index)
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
                    # Debug for specific functions
                    if func_name in ['XML_Parse', 'doProlog', 'doContent']:
                        print("DEBUG LLVM: Found " + func_name + " def, line: " + str(line[:80]) + "...")
                        print("DEBUG LLVM: params_str for " + func_name + ": '" + str(params_str[:80] if params_str else '') + "'")
                else:
                    params_str = ''
                    if func_name in ['XML_Parse', 'doProlog', 'doContent']:
                        print("DEBUG LLVM: Found " + func_name + " but NO parens!")
                
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
                    # Debug for specific functions
                    if func_name in ['XML_Parse', 'doProlog', 'doContent']:
                        print("DEBUG LLVM: Found " + func_name + " DECL, line: " + str(line[:80]) + "...")
                        print("DEBUG LLVM: params_str for " + func_name + " decl: '" + str(params_str[:80] if params_str else '') + "'")
                else:
                    params_str = ''
                    if func_name in ['XML_Parse', 'doProlog', 'doContent']:
                        print("DEBUG LLVM: Found " + func_name + " DECL but NO parens!")
                
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
                field_idx = int(match.group(3))
                self.gep_info[(current_func, dst_reg)] = (struct_type, field_idx)
            
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
        
        # Now resolve indirect calls.
        # Struct-field dispatch (e.g. expat's m_processor) can legitimately
        # have 15-20+ targets; allow up to 24 before considering imprecise.
        max_targets_per_call = 24
        for caller, ptr_name, location in self.indirect_calls:
            targets = self.pointer_targets.get((caller, ptr_name), set())
            if targets:
                if len(targets) > max_targets_per_call:
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
        
        # Debug: show specific functions we care about
        for func in ['contentProcessor', 'prologProcessor', 'doContent']:
            if func in self.address_taken:
                print("DEBUG LLVM: " + func + " is address-taken at: " + str(self.address_taken[func][:2]))
            else:
                print("DEBUG LLVM: " + func + " is NOT address-taken")
        
        # Debug: show first few store targets
        print("DEBUG LLVM: Sample pointer_targets: " + str(dict(list(self.pointer_targets.items())[:5])))
        
        # Resolve function pointers
        self.resolve_function_pointers()
        
        # Debug: show data params for key functions
        for func in ['XML_Parse', 'XML_FreeContentModel', 'doProlog', 'doContent']:
            data_params = self.get_data_params(func)
            all_params = self.func_params.get(func, [])
            print("DEBUG LLVM: " + func + " params: " + str(all_params[:3]) + " -> data_params: " + str(data_params))
        
        # Debug: show all functions that start with "XML" or contain "Parse"
        xml_funcs = [f for f in self.functions if 'XML' in f or 'arse' in f or 'arse' in f.lower()]
        print("DEBUG LLVM: Functions with 'XML' or 'Parse': " + str(xml_funcs[:10]))
        
        # Debug: show params for all XML_ functions
        for func in xml_funcs[:5]:
            print("DEBUG LLVM: " + func + " -> params: " + str(self.func_params.get(func, [])[:2]))
        
        # Debug: Check functions in callgraph but not in func_params
        all_callgraph_funcs = set(self.adjacency.keys())
        for callees in self.adjacency.values():
            all_callgraph_funcs.update(callees)
        missing_params = [f for f in all_callgraph_funcs if f not in self.func_params and f.startswith('XML')]
        print("DEBUG LLVM: XML functions in callgraph but missing params: " + str(missing_params[:10]))
        
        # Convert to expected format
        adjacency = {caller: list(callees) for caller, callees in self.adjacency.items()}
        usr_to_file = {name: info.get('location', '') for name, info in self.functions.items()}
        usr_to_name = {name: name for name in self.functions}
        
        return adjacency, usr_to_file, usr_to_name
    
    def score_path_taint(self, path):
        """
        Score a path based on taint propagation potential.
        Higher score = better path (more likely to pass external data to sink).
        
        Scoring:
        - Entry point with data params: +10
        - Each hop: -1 (prefer shorter paths)
        - Entry point with "Free/Destroy/Cleanup" in name: -5
        - Penalty for internal-looking function names (Xml* vs XML_*)
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
        
        # Penalty for cleanup functions
        entry_lower = entry.lower()
        if 'free' in entry_lower or 'destroy' in entry_lower or 'cleanup' in entry_lower:
            score -= 15
        if 'reset' in entry_lower or 'close' in entry_lower:
            score -= 10
        
        # Bonus for parse/process/handle/run functions (likely data processors)
        if 'parse' in entry_lower or 'process' in entry_lower:
            score += 8
        if 'handle' in entry_lower or 'run' in entry_lower or 'execute' in entry_lower:
            score += 5
        
        # SMALL penalty for each hop (prefer shorter paths, but not as much as data flow)
        score -= len(path) - 1

        # Score actual caller->callee parameter propagation along the chosen path.
        tainted_params = set(entry_data_params + entry_control_params)
        if tainted_params:
            score += 3
        for index in range(len(path) - 1):
            caller = path[index]
            callee = path[index + 1]
            edge_flow = self.get_edge_param_flow(caller, callee)
            if not edge_flow:
                score -= 2
                tainted_params = set()
                continue

            next_tainted = set()
            propagated = 0
            for caller_param_idx, callee_param_idx in edge_flow:
                if caller_param_idx in tainted_params:
                    next_tainted.add(callee_param_idx)
                    propagated += 1

            if propagated:
                score += 8 * propagated
                tainted_params = next_tainted
            else:
                score -= 1
                tainted_params = next_tainted

        # Extra bonus if some entry-controlled parameter evidence survives all the way to the sink.
        if tainted_params:
            score += 6 * len(tainted_params)
        
        # Heuristic: detect internal vs public function naming patterns
        # Many libraries use: LIBRARY_* for public, Library* for internal
        # Examples:
        #   expat: XML_Parse (public) vs XmlParseXmlDecl (internal)
        #   cJSON: cJSON_Parse (public) - no internal prefix conflict
        #   libpng: png_* functions
        #
        # Pattern: If function starts with uppercase followed by lowercase (Xml, Json, Png)
        # and contains another uppercase later, it's likely INTERNAL.
        # If function is ALL_CAPS prefix with underscore (XML_, JSON_, PNG_), it's PUBLIC.
        import re
        if entry and len(entry) > 1:
            # Check for internal pattern: Xxxx* (e.g., Xml, Json, Png followed by more)
            # These start with uppercase, then lowercase, then more chars
            internal_pattern = re.match(r'^[A-Z][a-z][a-zA-Z0-9]+', entry)
            if internal_pattern:
                # Looks like internal function (Xml*, Json*, etc.)
                # STRONG penalty - these should rarely be selected as entry points
                score -= 100
            
            # Check for public pattern: PREFIX_* (e.g., XML_, JSON_, PNG_)
            public_pattern = re.match(r'^[A-Z][A-Z0-9]*_', entry)
            if public_pattern:
                # Looks like public API (XML_Parse, JSON_Parse, etc.)
                score += 15
        
        return score


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

def score_path_taint(path):
    """
    Score a path using the global builder instance.
    Higher score = better path for fuzzing.
    """
    global _builder_instance
    if _builder_instance is None:
        # Return a default score if no builder
        return -len(path) if path else -1000
    return _builder_instance.score_path_taint(path)

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