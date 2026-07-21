"""Tests for the OSS-Fuzz-Gen-style harness synthesis repair loop."""

from __future__ import annotations

from clearwing.ossfuzz.builder import BuildResult
from clearwing.ossfuzz.project import OssFuzzProject
from clearwing.ossfuzz.synthesize import (
    HarnessSynthesizer,
    _default_harness_name,
    _render_single_harness_build_sh,
    _strip_markdown_fences,
)

GOOD_HARNESS = """\
#include <stdint.h>
#include <stddef.h>
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 4) return 0;
    return parse_header(Data, Size);
}
"""

BAD_HARNESS = "int LLVMFuzzerTestOneInput() { syntax error }"


class FakeResponse:
    def __init__(self, text):
        self._text = text

    def first_text(self):
        return self._text


class FakeLLM:
    """Queued LLM responses; records prompts for assertions."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls: list[dict] = []

    async def aask_text(self, system=None, user=None, **kw):
        self.calls.append({"system": system, "user": user})
        return FakeResponse(self._responses.pop(0) if self._responses else "")


class FakeBuilder:
    """Scripted builder: returns queued BuildResults, records calls."""

    def __init__(self, results):
        self._results = list(results)
        self.calls: list[dict] = []

    def build(self, project, project_dir, source_dir, out_dir, **kwargs):
        self.calls.append(kwargs)
        if self._results:
            return self._results.pop(0)
        return BuildResult(success=True, out_dir=str(out_dir), fuzzer_binaries=["fuzz_x"])


def _ok_build(out="/tmp/out"):
    return BuildResult(success=True, out_dir=out, fuzzer_binaries=["fuzz_parse"])


def _fail_build(log="error: implicit declaration of function 'parse_header'"):
    return BuildResult(success=False, error="build.sh exited 1", log=log)


class TestRepairLoop:
    def test_success_on_first_round(self, tmp_path):
        llm = FakeLLM([GOOD_HARNESS])
        builder = FakeBuilder([_ok_build()])
        synth = HarnessSynthesizer(llm, builder)
        project = OssFuzzProject(name="proj")

        result = synth.synthesize(
            project, tmp_path, tmp_path, tmp_path / "out",
            target_file="src/parse.c", file_source="int parse_header(...) {}",
        )
        assert result.success
        assert result.rounds == 1
        assert result.fuzzer_name.startswith("fuzz_parse-")
        assert result.harness_source == GOOD_HARNESS.strip()
        # Harness injected via extra_files, never the host tree
        extra = builder.calls[0]["extra_files"]
        assert list(extra) == ["/src/proj/.fuzzstage/" + result.fuzzer_name + ".c"]
        assert extra[list(extra)[0]].decode() == GOOD_HARNESS.strip()

    def test_repair_loop_feeds_stderr_back(self, tmp_path):
        llm = FakeLLM([BAD_HARNESS, GOOD_HARNESS])
        builder = FakeBuilder([_fail_build(), _ok_build()])
        synth = HarnessSynthesizer(llm, builder)
        project = OssFuzzProject(name="proj")

        result = synth.synthesize(
            project, tmp_path, tmp_path, tmp_path / "out",
            target_file="src/parse.c", file_source="...",
        )
        assert result.success
        assert result.rounds == 2
        # Second LLM call is a repair: previous harness + compiler output
        repair_call = llm.calls[1]
        assert "FAILING HARNESS" in repair_call["user"]
        assert BAD_HARNESS in repair_call["user"]
        assert "implicit declaration" in repair_call["user"]
        assert "fixing a libFuzzer harness" in repair_call["system"]

    def test_max_rounds_exhausted(self, tmp_path):
        llm = FakeLLM([BAD_HARNESS] * 4)
        builder = FakeBuilder([_fail_build()] * 4)
        synth = HarnessSynthesizer(llm, builder, max_rounds=3)
        project = OssFuzzProject(name="proj")

        result = synth.synthesize(
            project, tmp_path, tmp_path, tmp_path / "out",
            target_file="src/parse.c", file_source="...",
        )
        assert not result.success
        assert result.rounds == 3
        assert len(result.attempts) == 3
        assert len(builder.calls) == 3

    def test_llm_empty_response_counts_as_failed_round(self, tmp_path):
        llm = FakeLLM(["", GOOD_HARNESS])
        builder = FakeBuilder([_ok_build()])
        synth = HarnessSynthesizer(llm, builder)
        result = synth.synthesize(
            OssFuzzProject(name="proj"), tmp_path, tmp_path, tmp_path / "out",
            target_file="src/parse.c", file_source="...",
        )
        assert result.success
        assert result.rounds == 2
        assert len(builder.calls) == 1  # only the good harness was built

    def test_unsafe_target_path_fails_open(self, tmp_path):
        llm = FakeLLM([GOOD_HARNESS])
        builder = FakeBuilder([_ok_build()])
        synth = HarnessSynthesizer(llm, builder)
        result = synth.synthesize(
            OssFuzzProject(name="proj"), tmp_path, tmp_path, tmp_path / "out",
            target_file="../../../etc/passwd", file_source="...",
        )
        assert not result.success
        assert "unsafe repo-relative path" in result.attempts[-1].error_excerpt
        assert not builder.calls  # never reached the build

    def test_build_sh_override_uses_variables_and_quotes(self, tmp_path):
        llm = FakeLLM([GOOD_HARNESS])
        builder = FakeBuilder([_ok_build()])
        synth = HarnessSynthesizer(llm, builder)
        result = synth.synthesize(
            OssFuzzProject(name="proj"), tmp_path, tmp_path, tmp_path / "out",
            target_file="src/parse.c", file_source="...",
        )
        assert result.success
        build_sh = builder.calls[0]["build_sh_override"]
        assert "TARGET_FILE=src/parse.c" in build_sh
        assert '"$SRC/proj/$TARGET_FILE"' in build_sh
        assert '"$SRC/proj/$HARNESS"' in build_sh
        assert '-o "$OUT/fuzz_parse-' in build_sh

    def test_llm_exception_fail_open(self, tmp_path):
        class ExplodingLLM:
            async def aask_text(self, **kw):
                raise ConnectionError("endpoint down")

        synth = HarnessSynthesizer(ExplodingLLM(), FakeBuilder([_ok_build()]), max_rounds=2)
        result = synth.synthesize(
            OssFuzzProject(name="proj"), tmp_path, tmp_path, tmp_path / "out",
            target_file="src/parse.c", file_source="...",
        )
        assert not result.success  # fail-open, never raises


class TestHelpers:
    def test_default_names_unique_per_path(self):
        a = _default_harness_name("src/parser.c")
        b = _default_harness_name("vendor/parser.c")
        assert a != b
        assert a.startswith("fuzz_parser-")
        assert b.startswith("fuzz_parser-")

    def test_default_name_sanitizes_stem(self):
        name = _default_harness_name("src/My Parser$.c")
        stem_part = name.rsplit("-", 1)[0]
        assert stem_part == "fuzz_my-parser"

    def test_render_rejects_traversal(self):
        import pytest

        with pytest.raises(ValueError, match="unsafe repo-relative path"):
            _render_single_harness_build_sh(
                "proj", ".fuzzstage/x.c", "../escape.c", "fuzz_x", False,
            )

    def test_render_allows_spaces_via_quoting(self):
        sh = _render_single_harness_build_sh(
            "proj", ".fuzzstage/fuzz_x.c", "src/my parser.c", "fuzz_x", False,
        )
        assert "TARGET_FILE='src/my parser.c'" in sh

    def test_render_rejects_bad_fuzzer_name(self):
        import pytest

        with pytest.raises(ValueError, match="unsafe fuzzer name"):
            _render_single_harness_build_sh(
                "proj", ".fuzzstage/x.c", "src/a.c", "fuzz_$(rm -rf /)", False,
            )

    def test_strip_fences(self):
        fenced = "```c\nint x;\n```"
        assert _strip_markdown_fences(fenced) == "int x;"
        assert _strip_markdown_fences("int x;") == "int x;"
