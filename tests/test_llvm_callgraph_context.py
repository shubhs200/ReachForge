"""Regression tests for LLVM callgraph and header extraction fixes."""
import unittest
import sys, os
sys.path.insert(0, os.path.dirname(__file__))


class LLVMCallgraphContextTests(unittest.TestCase):
    """Tests for function-scoped pointer target resolution."""

    def test_ssa_names_scoped_by_function(self):
        """Numeric SSA names like %43 in different functions must not share targets."""
        from llvm_callgraph import LLVMCallGraphBuilder
        b = LLVMCallGraphBuilder()
        # Simulate: deflateCopy stores @zcalloc to %43
        b.functions['zcalloc'] = {'defined': True, 'location': 'a.ll:1', 'params': []}
        b.functions['hello'] = {'defined': True, 'location': 'a.ll:2', 'params': []}
        b.functions['deflateCopy'] = {'defined': True, 'location': 'a.ll:3', 'params': []}
        b.functions['otherFunc'] = {'defined': True, 'location': 'a.ll:4', 'params': []}

        # deflateCopy: store @zcalloc, %43
        b.func_ptr_stores.append(('43', 'zcalloc', 'a.ll:10', 'deflateCopy'))
        b.pointer_targets[('deflateCopy', '43')].add('zcalloc')

        # otherFunc: store @hello, %43 (different function, same SSA name)
        b.func_ptr_stores.append(('43', 'hello', 'a.ll:20', 'otherFunc'))
        b.pointer_targets[('otherFunc', '43')].add('hello')

        # deflateCopy has indirect call via %43
        b.indirect_calls.append(('deflateCopy', '43', 'a.ll:15'))
        # otherFunc has indirect call via %43
        b.indirect_calls.append(('otherFunc', '43', 'a.ll:25'))

        b.resolve_function_pointers()

        # deflateCopy -> zcalloc only, NOT hello
        self.assertIn('zcalloc', b.adjacency['deflateCopy'])
        self.assertNotIn('hello', b.adjacency['deflateCopy'],
                         "hello leaked from otherFunc's %43 scope into deflateCopy")

        # otherFunc -> hello only, NOT zcalloc
        self.assertIn('hello', b.adjacency['otherFunc'])
        self.assertNotIn('zcalloc', b.adjacency['otherFunc'],
                         "zcalloc leaked from deflateCopy's %43 scope into otherFunc")

    def test_propagation_stays_within_function(self):
        """Pointer-to-pointer propagation must stay within the same function."""
        from llvm_callgraph import LLVMCallGraphBuilder
        b = LLVMCallGraphBuilder()
        b.functions['targetA'] = {'defined': True, 'location': 'a.ll:1', 'params': []}
        b.functions['targetB'] = {'defined': True, 'location': 'a.ll:2', 'params': []}
        b.functions['funcX'] = {'defined': True, 'location': 'a.ll:3', 'params': []}
        b.functions['funcY'] = {'defined': True, 'location': 'a.ll:4', 'params': []}

        # funcX: store @targetA -> %10, then load %10 -> %20, call %20
        b.func_ptr_stores.append(('10', 'targetA', 'a.ll:10', 'funcX'))
        b.pointer_targets[('funcX', '10')].add('targetA')
        b.func_ptr_stores.append(('20', '10', 'a.ll:11', 'funcX'))  # propagation
        b.indirect_calls.append(('funcX', '20', 'a.ll:12'))

        # funcY: store @targetB -> %10, then load %10 -> %20, call %20
        b.func_ptr_stores.append(('10', 'targetB', 'a.ll:20', 'funcY'))
        b.pointer_targets[('funcY', '10')].add('targetB')
        b.func_ptr_stores.append(('20', '10', 'a.ll:21', 'funcY'))
        b.indirect_calls.append(('funcY', '20', 'a.ll:22'))

        b.resolve_function_pointers()

        self.assertIn('targetA', b.adjacency['funcX'])
        self.assertNotIn('targetB', b.adjacency['funcX'])
        self.assertIn('targetB', b.adjacency['funcY'])
        self.assertNotIn('targetA', b.adjacency['funcY'])


class HeaderParamExtractionTests(unittest.TestCase):
    """Tests for comment stripping and prose rejection in header param parsing."""

    def test_parse_params_rejects_prose_type(self):
        """parse_params_string must reject English prose that looks like type + name."""
        from public_api import parse_params_string
        # This came from a comment: "If the file has been previously opened with fopen"
        result = parse_params_string('if the file has been previously opened with, fopen')
        names = [n for _, n in result]
        self.assertNotIn('fopen', names,
                         "English prose from a comment should not parse as a parameter")

    def test_parse_params_rejects_quoted_strings(self):
        """parse_params_string must reject quoted string fragments as types."""
        from public_api import parse_params_string
        result = parse_params_string('"rb" or, "wb"')
        self.assertEqual(result, [],
                         "Quoted string fragments should not parse as parameters")

    def test_parse_params_accepts_valid_c_types(self):
        """parse_params_string must still accept normal C parameter declarations."""
        from public_api import parse_params_string
        result = parse_params_string('const char *name, int mode')
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0], ('const char', 'name'))
        self.assertEqual(result[1], ('int', 'mode'))

    def test_looks_like_c_type_basic(self):
        """_looks_like_c_type correctly classifies types vs prose."""
        from public_api import _looks_like_c_type
        # Valid C types
        self.assertTrue(_looks_like_c_type('int'))
        self.assertTrue(_looks_like_c_type('const char'))
        self.assertTrue(_looks_like_c_type('void *'))
        self.assertTrue(_looks_like_c_type('size_t'))
        # Prose / garbage
        self.assertFalse(_looks_like_c_type('"rb" or'))
        self.assertFalse(_looks_like_c_type('if the file has been previously opened with'))
        self.assertFalse(_looks_like_c_type('the quick brown fox'))


class StageRetrievalFilteringTests(unittest.TestCase):
    """Tests for _is_low_priority_path filtering in stage_retrieval."""

    def test_python_bindings_are_low_priority(self):
        """Python binding directories should be filtered as low-priority."""
        from stage_retrieval import _is_low_priority_path
        self.assertTrue(_is_low_priority_path('python/libxml2.py'))
        self.assertTrue(_is_low_priority_path('src/python/module.c'))
        self.assertTrue(_is_low_priority_path('bindings/python/wrap.c'))
        self.assertTrue(_is_low_priority_path('wrappers/csharp/glue.cs'))
        self.assertTrue(_is_low_priority_path('swig/libxml2.i'))

    def test_normal_source_files_not_low_priority(self):
        """Regular library source files should NOT be low-priority."""
        from stage_retrieval import _is_low_priority_path
        self.assertFalse(_is_low_priority_path('src/parser.c'))
        self.assertFalse(_is_low_priority_path('lib/decode.c'))
        self.assertFalse(_is_low_priority_path('include/api.h'))

    def test_is_buffer_like_rejects_callbacks(self):
        """_is_buffer_like_field must reject SAX/callback-style field names."""
        from contract_inference import _is_buffer_like_field
        # Callback-like fields
        self.assertFalse(_is_buffer_like_field('endDocument'))
        self.assertFalse(_is_buffer_like_field('startElement'))
        self.assertFalse(_is_buffer_like_field('characters'))
        self.assertFalse(_is_buffer_like_field('error_handler'))
        self.assertFalse(_is_buffer_like_field('fatalError'))
        # Real buffer fields should still be detected
        self.assertTrue(_is_buffer_like_field('extra'))
        self.assertTrue(_is_buffer_like_field('buffer'))
        self.assertTrue(_is_buffer_like_field('data'))

    def test_is_internal_intermediary(self):
        """_is_internal_intermediary must flag deep-chain structs."""
        from contract_inference import _is_internal_intermediary
        # 3-part chains -> internal
        self.assertTrue(_is_internal_intermediary('input', ['ctxt', 'input', 'buf']))
        self.assertTrue(_is_internal_intermediary('buf', ['input', 'buf', 'buffer']))
        # 2-part chains -> not automatically internal (needs state owner check)
        self.assertFalse(_is_internal_intermediary('input', ['ctxt', 'input']))
        # Real support objects should not be flagged
        self.assertFalse(_is_internal_intermediary('head', ['ctxt', 'head', 'extra']))
        self.assertFalse(_is_internal_intermediary('header', ['state', 'header', 'data']))


class StateFieldExtractionTests(unittest.TestCase):
    """Tests for local-variable filtering in state_fields extraction."""

    def test_state_fields_excludes_return_value_locals(self):
        """Common return-value locals like 'ret', 'result' should be excluded."""
        from vuln_analyzer import extract_state_fields
        source = """
        xmlEntityPtr ret = xmlCreateEntity(doc, name, type, NULL, NULL, content);
        if (ret == NULL) return;
        ret->doc = doc;
        ret->name = name;
        result->field = val;
        """
        fields = extract_state_fields(source)
        owners = {f['owner'] for f in fields}
        self.assertNotIn('ret', owners,
                         "'ret' is a local return variable, should be excluded")
        self.assertNotIn('result', owners,
                         "'result' is a local return variable, should be excluded")

    def test_state_fields_keeps_legitimate_struct_owners(self):
        """Legitimate struct owners like 'dtd', 'head', 'strm' should be kept."""
        from vuln_analyzer import extract_state_fields
        source = """
        dtd->doc = doc;
        dtd->entities = xmlHashCreate(0);
        head->extra = buf;
        head->extra_max = max_len;
        strm->next_in = data;
        """
        fields = extract_state_fields(source)
        owners = {f['owner'] for f in fields}
        self.assertIn('dtd', owners)
        self.assertIn('head', owners)
        self.assertIn('strm', owners)

    def test_is_buffer_like_field_rejects_structural_pointers(self):
        """Fields like 'doc', 'entities', 'parent' are structural pointers,
        not buffers, and should NOT be classified as buffer-like."""
        from contract_inference import _is_buffer_like_field
        # Structural pointer fields
        self.assertFalse(_is_buffer_like_field('doc'))
        self.assertFalse(_is_buffer_like_field('entities'))
        self.assertFalse(_is_buffer_like_field('pentities'))
        self.assertFalse(_is_buffer_like_field('parent'))
        self.assertFalse(_is_buffer_like_field('children'))
        # Real buffer fields should still be detected
        self.assertTrue(_is_buffer_like_field('extra'))
        self.assertTrue(_is_buffer_like_field('buffer'))
        self.assertTrue(_is_buffer_like_field('data'))
        self.assertTrue(_is_buffer_like_field('src'))

    def test_load_from_global_resolves_indirect_call(self):
        """Loading from a global variable like @xmlMalloc that is also a known
        function should resolve the indirect call."""
        from llvm_callgraph import LLVMCallGraphBuilder
        b = LLVMCallGraphBuilder()
        b.functions['xmlMalloc'] = {'defined': True, 'location': 'a.ll:1', 'params': []}
        b.functions['xmlNewEntity'] = {'defined': True, 'location': 'a.ll:2', 'params': []}

        # Simulate: %15 = load ... @xmlMalloc  then  call %15(...)
        # The load_global_pattern handler should add xmlMalloc to pointer_targets
        b.pointer_targets[('xmlNewEntity', '15')].add('xmlMalloc')
        b.indirect_calls.append(('xmlNewEntity', '15', 'entities.ll:686'))

        b.resolve_function_pointers()

        self.assertIn('xmlMalloc', b.adjacency['xmlNewEntity'],
                      "Global function pointer load @xmlMalloc not resolved")

    def test_load_global_pattern_matches_ir(self):
        """The load_global_pattern regex must capture loads from @global vars."""
        from llvm_callgraph import LLVMCallGraphBuilder
        b = LLVMCallGraphBuilder()
        line = '  %15 = load i8* (i64)*, i8* (i64)** @xmlMalloc, align 8'
        m = b.load_global_pattern.search(line)
        self.assertIsNotNone(m, "load_global_pattern failed to match global load")
        self.assertEqual(m.group(1), '15')
        self.assertEqual(m.group(2), 'xmlMalloc')

    def test_load_pattern_matches_both_local_and_global(self):
        """The general load_pattern should match both %src and @src loads."""
        from llvm_callgraph import LLVMCallGraphBuilder
        b = LLVMCallGraphBuilder()
        # Local load
        local = '  %10 = load void ()*, void ()** %func_ptr, align 8'
        m1 = b.load_pattern.search(local)
        self.assertIsNotNone(m1)
        self.assertEqual(m1.group(2), 'func_ptr')
        # Global load
        global_l = '  %15 = load i8* (i64)*, i8* (i64)** @xmlMalloc, align 8'
        m2 = b.load_pattern.search(global_l)
        self.assertIsNotNone(m2)
        self.assertEqual(m2.group(2), 'xmlMalloc')

    def test_bfs_prefers_caller_over_sink_self_path(self):
        """When the sink is itself a public API, the BFS should prefer a
        caller path over the trivial length-1 self-path."""
        # name_adjacency: callee -> [callers]  (reverse adjacency)
        name_adjacency = {
            'xmlBufAttrSerializeTxtContent': [
                'xmlAttrSerializeTxtContent',
                'xmlTextWriterWriteString',
            ]
        }
        public_api_names = {
            'xmlBufAttrSerializeTxtContent',
            'xmlAttrSerializeTxtContent',
            'xmlTextWriterWriteString',
        }
        sink_name = 'xmlBufAttrSerializeTxtContent'

        from collections import deque
        queue = deque([[sink_name]])
        visited = set([sink_name])
        all_paths = []
        sink_self_path = None

        while queue:
            path = queue.popleft()
            cur = path[0]
            if cur in public_api_names:
                if len(path) == 1 and cur == sink_name:
                    sink_self_path = path
                    # Do NOT continue — explore callers of the sink
                else:
                    all_paths.append(path)
                    continue
            callers = sorted(name_adjacency.get(cur, []))
            for caller in callers:
                if caller not in visited:
                    visited.add(caller)
                    new_path = [caller] + path
                    queue.append(new_path)

        if not all_paths and sink_self_path:
            all_paths.append(sink_self_path)

        # Caller paths must be found, not the self-path
        self.assertTrue(len(all_paths) >= 2,
                        "Should find at least 2 caller paths, got: " + str(all_paths))
        for p in all_paths:
            self.assertGreater(len(p), 1,
                               "Self-path should NOT be in all_paths when callers exist: " + str(p))

    def test_bfs_falls_back_to_self_when_no_callers_reach_public_api(self):
        """If no caller path reaches a public API, the self-path must still be used."""
        # internalHelper is NOT a public API, so the BFS from sink can't find
        # a caller that is public.
        name_adjacency = {
            'mySink': ['internalHelper']
        }
        public_api_names = {'mySink'}  # only the sink
        sink_name = 'mySink'

        from collections import deque
        queue = deque([[sink_name]])
        visited = set([sink_name])
        all_paths = []
        sink_self_path = None

        while queue:
            path = queue.popleft()
            cur = path[0]
            if cur in public_api_names:
                if len(path) == 1 and cur == sink_name:
                    sink_self_path = path
                else:
                    all_paths.append(path)
                    continue
            callers = sorted(name_adjacency.get(cur, []))
            for caller in callers:
                if caller not in visited:
                    visited.add(caller)
                    new_path = [caller] + path
                    queue.append(new_path)

        if not all_paths and sink_self_path:
            all_paths.append(sink_self_path)

        self.assertEqual(len(all_paths), 1)
        self.assertEqual(all_paths[0], ['mySink'],
                         "Should fall back to self-path when no caller is a public API")


class CompileHarnessExtraLibTests(unittest.TestCase):
    """Tests for auto-detection of transitive library dependencies."""

    def test_detect_extra_libs_finds_lzma(self):
        """_detect_extra_libs should return -llzma when nm reports lzma_ symbols."""
        import tempfile, subprocess
        from unittest import mock
        from compile_harness import _detect_extra_libs

        nm_output = (
            "                 U lzma_auto_decoder\n"
            "                 U lzma_code\n"
            "                 U lzma_end\n"
        )
        fake_result = mock.Mock(returncode=0, stdout=nm_output.encode())
        with mock.patch('compile_harness.subprocess.run', return_value=fake_result):
            libs = _detect_extra_libs('/fake/libxml2.a', 'xml2')
        self.assertIn('-llzma', libs)

    def test_detect_extra_libs_skips_self(self):
        """_detect_extra_libs should NOT add -llzma when the library IS lzma."""
        from unittest import mock
        from compile_harness import _detect_extra_libs

        nm_output = "                 U lzma_auto_decoder\n"
        fake_result = mock.Mock(returncode=0, stdout=nm_output.encode())
        with mock.patch('compile_harness.subprocess.run', return_value=fake_result):
            libs = _detect_extra_libs('/fake/liblzma.a', 'lzma')
        self.assertNotIn('-llzma', libs)

    def test_detect_extra_libs_empty_on_no_symbols(self):
        """_detect_extra_libs returns empty list when no known prefixes found."""
        from unittest import mock
        from compile_harness import _detect_extra_libs

        nm_output = "                 U xmlParseDocument\n"
        fake_result = mock.Mock(returncode=0, stdout=nm_output.encode())
        with mock.patch('compile_harness.subprocess.run', return_value=fake_result):
            libs = _detect_extra_libs('/fake/libxml2.a', 'xml2')
        self.assertEqual(libs, [])

    def test_detect_extra_libs_finds_zlib(self):
        """_detect_extra_libs should return -lz when nm reports deflate/inflate symbols."""
        from unittest import mock
        from compile_harness import _detect_extra_libs

        nm_output = (
            "                 U deflateInit2_\n"
            "                 U inflate\n"
        )
        fake_result = mock.Mock(returncode=0, stdout=nm_output.encode())
        with mock.patch('compile_harness.subprocess.run', return_value=fake_result):
            libs = _detect_extra_libs('/fake/libpng.a', 'png')
        self.assertIn('-lz', libs)

    def test_detect_extra_libs_no_zlib_for_expat(self):
        """_detect_extra_libs should NOT return -lz when no zlib symbols present."""
        from unittest import mock
        from compile_harness import _detect_extra_libs

        nm_output = (
            "                 U malloc\n"
            "                 U free\n"
            "                 U memcpy\n"
        )
        fake_result = mock.Mock(returncode=0, stdout=nm_output.encode())
        with mock.patch('compile_harness.subprocess.run', return_value=fake_result):
            libs = _detect_extra_libs('/fake/libexpat.a', 'expat')
        self.assertNotIn('-lz', libs)


class TestStructFieldGEPTracking(unittest.TestCase):
    """Cross-function struct-field function pointer resolution."""

    def _make_ll(self, content):
        """Write content to a temp .ll file and return the path."""
        import tempfile
        f = tempfile.NamedTemporaryFile(mode='w', suffix='.ll', delete=False)
        f.write(content)
        f.close()
        return f.name

    def test_store_pattern_complex_fptr_type(self):
        """store_pattern must capture the register, not the %struct type."""
        from llvm_callgraph import LLVMCallGraphBuilder
        b = LLVMCallGraphBuilder()
        m = b.store_pattern.search(
            '  store i32 (%struct.XML_ParserStruct*, i8*, i8*, i8**)* '
            '@prologInitProcessor, i32 (%struct.XML_ParserStruct*, i8*, '
            'i8*, i8**)** %6, align 8'
        )
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), 'prologInitProcessor')
        self.assertEqual(m.group(2), '6')

    def test_load_pattern_complex_fptr_type(self):
        """load_pattern must capture the source register, not the %struct type."""
        from llvm_callgraph import LLVMCallGraphBuilder
        b = LLVMCallGraphBuilder()
        m = b.load_pattern.search(
            '  %82 = load i32 (%struct.XML_ParserStruct*, i8*, i8*, i8**)*, '
            'i32 (%struct.XML_ParserStruct*, i8*, i8*, i8**)** %81, align 8'
        )
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), '82')
        self.assertEqual(m.group(2), '81')

    def test_cross_function_struct_field_resolution(self):
        """Function pointer stored via GEP in one func, loaded via GEP in another."""
        from llvm_callgraph import LLVMCallGraphBuilder
        ir = (
            'define void @setter(%struct.S* %s) {\n'
            '  %1 = getelementptr inbounds %struct.S, %struct.S* %s, i32 0, i32 3\n'
            '  store void ()* @target_func, void ()** %1, align 8\n'
            '  ret void\n'
            '}\n'
            'define void @caller(%struct.S* %s) {\n'
            '  %1 = getelementptr inbounds %struct.S, %struct.S* %s, i32 0, i32 3\n'
            '  %2 = load void ()*, void ()** %1, align 8\n'
            '  call void %2()\n'
            '  ret void\n'
            '}\n'
            'define void @target_func() {\n'
            '  ret void\n'
            '}\n'
        )
        ll_path = self._make_ll(ir)
        b = LLVMCallGraphBuilder()
        adj, _, _ = b.build_callgraph([ll_path])
        import os; os.unlink(ll_path)
        self.assertIn('target_func', adj.get('caller', []),
                       'caller should reach target_func via struct field GEP')

    def test_struct_field_different_fields_no_crosstalk(self):
        """Different struct fields must not share function pointer targets."""
        from llvm_callgraph import LLVMCallGraphBuilder
        ir = (
            'define void @setter(%struct.S* %s) {\n'
            '  %1 = getelementptr inbounds %struct.S, %struct.S* %s, i32 0, i32 3\n'
            '  store void ()* @func_a, void ()** %1, align 8\n'
            '  %2 = getelementptr inbounds %struct.S, %struct.S* %s, i32 0, i32 5\n'
            '  store void ()* @func_b, void ()** %2, align 8\n'
            '  ret void\n'
            '}\n'
            'define void @caller(%struct.S* %s) {\n'
            '  %1 = getelementptr inbounds %struct.S, %struct.S* %s, i32 0, i32 3\n'
            '  %2 = load void ()*, void ()** %1, align 8\n'
            '  call void %2()\n'
            '  ret void\n'
            '}\n'
            'define void @func_a() { ret void }\n'
            'define void @func_b() { ret void }\n'
        )
        ll_path = self._make_ll(ir)
        b = LLVMCallGraphBuilder()
        adj, _, _ = b.build_callgraph([ll_path])
        import os; os.unlink(ll_path)
        callees = adj.get('caller', [])
        self.assertIn('func_a', callees, 'caller loads field 3 which has func_a')
        self.assertNotIn('func_b', callees, 'func_b is in field 5, not field 3')

    def test_expat_processor_pattern(self):
        """Expat-style pattern: parserInit stores processor, XML_Parse loads and calls it."""
        from llvm_callgraph import LLVMCallGraphBuilder
        ir = (
            'define void @parserInit(%struct.XML_ParserStruct* %0, i8* %1) {\n'
            '  %3 = alloca %struct.XML_ParserStruct*, align 8\n'
            '  store %struct.XML_ParserStruct* %0, %struct.XML_ParserStruct** %3, align 8\n'
            '  %5 = load %struct.XML_ParserStruct*, %struct.XML_ParserStruct** %3, align 8\n'
            '  %6 = getelementptr inbounds %struct.XML_ParserStruct, %struct.XML_ParserStruct* %5, i32 0, i32 45\n'
            '  store i32 (%struct.XML_ParserStruct*, i8*, i8*, i8**)* @prologInitProcessor, i32 (%struct.XML_ParserStruct*, i8*, i8*, i8**)** %6, align 8\n'
            '  ret void\n'
            '}\n'
            'define i32 @XML_Parse(%struct.XML_ParserStruct* %0, i8* %1, i32 %2, i32 %3) {\n'
            '  %5 = alloca %struct.XML_ParserStruct*, align 8\n'
            '  store %struct.XML_ParserStruct* %0, %struct.XML_ParserStruct** %5, align 8\n'
            '  %80 = load %struct.XML_ParserStruct*, %struct.XML_ParserStruct** %5, align 8\n'
            '  %81 = getelementptr inbounds %struct.XML_ParserStruct, %struct.XML_ParserStruct* %80, i32 0, i32 45\n'
            '  %82 = load i32 (%struct.XML_ParserStruct*, i8*, i8*, i8**)*, i32 (%struct.XML_ParserStruct*, i8*, i8*, i8**)** %81, align 8\n'
            '  %83 = load %struct.XML_ParserStruct*, %struct.XML_ParserStruct** %5, align 8\n'
            '  %92 = call i32 %82(%struct.XML_ParserStruct* %83, i8* %1, i8* %1, i8** %5)\n'
            '  ret i32 %92\n'
            '}\n'
            'define i32 @prologInitProcessor(%struct.XML_ParserStruct* %0, i8* %1, i8* %2, i8** %3) {\n'
            '  ret i32 0\n'
            '}\n'
        )
        ll_path = self._make_ll(ir)
        b = LLVMCallGraphBuilder()
        adj, _, _ = b.build_callgraph([ll_path])
        import os; os.unlink(ll_path)
        self.assertIn('prologInitProcessor', adj.get('XML_Parse', []),
                       'XML_Parse should resolve indirect call to prologInitProcessor via struct field 45')


class PromptHarnessDescriptionTests(unittest.TestCase):
    """Test that the harness prompt correctly handles vulnerability description and call-path semantics."""

    def _make_minimal_plan(self, entry, call_path_names=None):
        """Create a minimal plan dict for prompt testing."""
        return {
            'vuln_entry': entry,
            'sink_usr': entry.get('affected-function', ''),
            'wrapper_path': ['sink_usr', 'wrapper_usr'],
            'usr_to_file': {},
            'usr_to_name': {},
            'public_api_name': 'TestAPI',
            'vuln_context': {},
            'execution_plan': {
                'call_path': call_path_names or [],
                'input_model': {},
                'parameter_roles': [],
            },
            'trigger_plan': {},
            'construction_plan': {},
        }

    def test_description_field_appears_in_prompt(self):
        """When entry has description, it should appear prominently in the prompt."""
        import tempfile, json
        from pathlib import Path
        from prompt_harness import build_harness_prompt

        entry = {
            'cve-id': 'CVE-2021-45960',
            'package-name': 'expat',
            'cwe-id': 'CWE-190',
            'affected-file': 'xmlparse.c',
            'affected-function': 'storeAtts',
            'description': 'A left shift by 29 or more places in storeAtts triggers realloc misbehavior when there are many namespace-prefixed attributes.',
        }
        plan = self._make_minimal_plan(entry, ['storeAtts', 'doContent', 'contentProcessor', 'XML_Parse'])

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            plan_path = root / 'harness_plan.json'
            plan_path.write_text(json.dumps(plan), encoding='utf-8')
            out_dir = root / 'out'
            prompt_path = build_harness_prompt(root, plan_path, out_dir)
            content = prompt_path.read_text(encoding='utf-8')

        self.assertIn('Vulnerability Description (from advisory)', content)
        self.assertIn('namespace-prefixed attributes', content)
        self.assertIn('CRITICAL', content)

    def test_no_description_field_no_section(self):
        """When entry lacks description, the description section should not appear."""
        import tempfile, json
        from pathlib import Path
        from prompt_harness import build_harness_prompt

        entry = {
            'cve-id': 'CVE-2025-64505',
            'package-name': 'libpng',
            'cwe-id': 'CWE-125',
            'affected-file': 'pngrtran.c',
            'affected-function': 'png_do_quantize',
        }
        plan = self._make_minimal_plan(entry)

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            plan_path = root / 'harness_plan.json'
            plan_path.write_text(json.dumps(plan), encoding='utf-8')
            out_dir = root / 'out'
            prompt_path = build_harness_prompt(root, plan_path, out_dir)
            content = prompt_path.read_text(encoding='utf-8')

        self.assertNotIn('Vulnerability Description (from advisory)', content)

    def test_call_path_semantic_section_present(self):
        """When call path has 2+ functions, the semantic analysis section should appear."""
        import tempfile, json
        from pathlib import Path
        from prompt_harness import build_harness_prompt

        entry = {
            'cve-id': 'CVE-2021-45960',
            'package-name': 'expat',
            'cwe-id': 'CWE-190',
            'affected-file': 'xmlparse.c',
            'affected-function': 'storeAtts',
        }
        plan = self._make_minimal_plan(entry, ['storeAtts', 'doContent', 'contentProcessor', 'XML_Parse'])

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            plan_path = root / 'harness_plan.json'
            plan_path.write_text(json.dumps(plan), encoding='utf-8')
            out_dir = root / 'out'
            prompt_path = build_harness_prompt(root, plan_path, out_dir)
            content = prompt_path.read_text(encoding='utf-8')

        self.assertIn('Call-Path Semantic Analysis', content)
        self.assertIn('storeAtts', content)
        self.assertIn('doContent', content)
        # CWE-190 specific guidance about many iterations
        self.assertIn('Integer Overflow Path Guidance', content)
        self.assertIn('many iterations', content)

    def test_cwe190_guidance_mentions_structured_elements(self):
        """CWE-190 guidance should mention structured element counts, not just raw integers."""
        from prompt_harness import get_cwe_guidance
        guidance = get_cwe_guidance('CWE-190')
        combined = ' '.join(guidance.get('harness_guidance', []))
        self.assertIn('LARGE NUMBER', combined)
        self.assertIn('namespace-prefixed', combined)
        self.assertIn('attributes', combined)


if __name__ == '__main__':
    unittest.main()
