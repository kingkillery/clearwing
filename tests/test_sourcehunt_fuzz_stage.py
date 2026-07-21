"""Tests for the sourcehunt fuzz stage (OSS-Fuzz-backed crash-first seeding)."""

from __future__ import annotations

import pytest

from clearwing.ossfuzz.crashes import parse_sanitizer_report
from clearwing.ossfuzz.runner import CrashArtifact, FuzzRunResult
from clearwing.ossfuzz.synthesize import SynthesisResult
from clearwing.sourcehunt import fuzz_stage
from clearwing.sourcehunt.fuzz_stage import (
    FuzzStageConfig,
    _harness_name,
    _sanitize_name,
    _select_eligible,
    run_fuzz_stage,
)

ASAN_TAIL = """\
==42==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x6020000000f1
    #1 0x55555555bbbb in parse_header /src/myproj/src/parse.c:217:9
SUMMARY: AddressSanitizer: heap-buffer-overflow /src/myproj/src/parse.c:217:9
"""


def _file_target(tmp_path, rel="src/parse.c", **overrides):
    abs_path = tmp_path / "repo" / rel
    abs_path.parent.mkdir(parents=True, exist_ok=True)
    abs_path.write_text("int parse_header(const unsigned char*d, unsigned long n){return 0;}\n")
    ft = {
        "path": rel,
        "absolute_path": str(abs_path),
        "surface": 4,
        "tags": ["parser", "fuzzable"],
        "language": "c",
        "priority": 3.5,
    }
    ft.update(overrides)
    return ft


class FakeSynthesizer:
    def __init__(self, llm, builder, *, max_rounds=4):
        self.results = {}

    def synthesize(self, project, project_dir, source_dir, out_dir, *, target_file, **kw):
        r = self.results.get(target_file)
        if isinstance(r, Exception):
            raise r
        return r or SynthesisResult(success=False, rounds=4)


class FakeRunner:
    def __init__(self, config):
        self.runs = {}

    def fuzz(self, out_dir, fuzzer_name):
        r = self.runs.get(fuzzer_name)
        if isinstance(r, Exception):
            raise r
        return r or FuzzRunResult(fuzzer_name=fuzzer_name, success=True)


def _crashing_run(fuzzer_name):
    report = parse_sanitizer_report(ASAN_TAIL)
    new = CrashArtifact(
        fuzzer_name=fuzzer_name,
        artifact_name="crash-aaa",
        input_path="/host/crash-aaa",
        report=report,
        signature="sig-1",
        is_new=True,
    )
    dup = CrashArtifact(
        fuzzer_name=fuzzer_name,
        artifact_name="crash-bbb",
        input_path="/host/crash-bbb",
        report=report,
        signature="sig-1",
        is_new=False,
    )
    return FuzzRunResult(
        fuzzer_name=fuzzer_name,
        success=True,
        crashes=[new, dup],
        unique_crash_count=1,
    )


@pytest.fixture
def patched(monkeypatch):
    synth = FakeSynthesizer(None, None)
    runner = FakeRunner(None)
    monkeypatch.setattr(fuzz_stage, "HarnessSynthesizer", lambda *a, **k: synth)
    monkeypatch.setattr(fuzz_stage, "FuzzRunner", lambda *a, **k: runner)
    monkeypatch.setattr(fuzz_stage, "OssFuzzBuilder", lambda *a, **k: object())
    return synth, runner


class TestSelection:
    def test_eligible_filters(self, tmp_path):
        good = _file_target(tmp_path, "src/a.c")
        low_surface = _file_target(tmp_path, "src/b.c", surface=2)
        wrong_lang = _file_target(tmp_path, "src/c.py", language="python")
        no_tags = _file_target(tmp_path, "src/d.c", tags=["crypto"])
        cfg = FuzzStageConfig()
        eligible = _select_eligible([good, low_surface, wrong_lang, no_tags], cfg)
        assert [ft["path"] for ft in eligible] == ["src/a.c"]

    def test_harness_name_unique_per_path(self):
        a = _harness_name("src/parser.c")
        b = _harness_name("vendor/parser.c")
        assert a != b
        assert a.startswith("fuzz_src-parser-c-")
        assert b.startswith("fuzz_vendor-parser-c-")

    def test_sanitize_name(self):
        assert _sanitize_name("My Repo!") == "my-repo"
        assert _sanitize_name("123") == "123"


class TestRunFuzzStage:
    def test_full_flow(self, tmp_path, patched):
        synth, runner = patched
        ft = _file_target(tmp_path)
        harness = _harness_name(ft["path"])
        synth.results[ft["path"]] = SynthesisResult(
            success=True, harness_source="// harness", fuzzer_name=harness, rounds=2,
        )
        runner.runs[harness] = _crashing_run(harness)

        result = run_fuzz_stage(
            [ft], str(tmp_path / "repo"), object(),
            work_dir=tmp_path / "work", session_id="sess-1",
        )
        assert result.harnesses_attempted == 1
        assert result.harnesses_succeeded == 1
        assert result.crashes == 2
        assert result.unique_crashes == 1
        assert not result.errors

        # Channel 1: seeded crash keyed by the FUZZED FILE's path
        assert len(result.seeded_crashes) == 1
        seed = result.seeded_crashes[0]
        assert seed.file == "src/parse.c"
        assert seed.target_function == "parse_header"
        assert "heap-buffer-overflow" in seed.report
        assert seed.harness_source == "// harness"

        # Channel 2: one finding (dup filtered) at crash_reproduced
        assert len(result.findings) == 1
        finding = result.findings[0]
        assert finding.evidence_level == "crash_reproduced"
        assert finding.extra["fuzz_stage_harness"] == harness
        assert finding.hunter_session_id == "sess-1"

    def test_synthesis_failure_is_not_fatal(self, tmp_path, patched):
        synth, _ = patched
        ft = _file_target(tmp_path)
        synth.results[ft["path"]] = SynthesisResult(success=False, rounds=4)
        result = run_fuzz_stage([ft], str(tmp_path / "repo"), object(), work_dir=tmp_path / "w")
        assert result.harnesses_attempted == 1
        assert result.harnesses_succeeded == 0
        assert not result.seeded_crashes
        assert not result.findings

    def test_synthesis_exception_captured(self, tmp_path, patched):
        synth, _ = patched
        ft = _file_target(tmp_path)
        synth.results[ft["path"]] = RuntimeError("docker exploded")
        result = run_fuzz_stage([ft], str(tmp_path / "repo"), object(), work_dir=tmp_path / "w")
        assert any("docker exploded" in e for e in result.errors)

    def test_finding_file_fallback_to_fuzzed_file(self, tmp_path, patched):
        """Crashes whose frames don't resolve still land on the fuzzed file."""
        synth, runner = patched
        ft = _file_target(tmp_path)
        harness = _harness_name(ft["path"])
        synth.results[ft["path"]] = SynthesisResult(
            success=True, harness_source="", fuzzer_name=harness, rounds=1,
        )
        empty_report_run = FuzzRunResult(
            fuzzer_name=harness,
            success=True,
            crashes=[
                CrashArtifact(
                    fuzzer_name=harness,
                    artifact_name="crash-x",
                    report=parse_sanitizer_report("==1==ERROR: libFuzzer: deadly signal\n"),
                    signature="sig-z",
                    is_new=True,
                )
            ],
            unique_crash_count=1,
        )
        runner.runs[harness] = empty_report_run
        result = run_fuzz_stage([ft], str(tmp_path / "repo"), object(), work_dir=tmp_path / "w")
        assert len(result.findings) == 1
        assert result.findings[0].file == "src/parse.c"

    def test_no_eligible_files(self, tmp_path, patched):
        result = run_fuzz_stage([], str(tmp_path), object(), work_dir=tmp_path / "w")
        assert result.harnesses_attempted == 0
        assert not result.findings

    def test_time_budget_stops_stage(self, tmp_path, patched):
        cfg = FuzzStageConfig(total_time_budget_seconds=-1)  # already expired
        ft = _file_target(tmp_path)
        result = run_fuzz_stage(
            [ft], str(tmp_path / "repo"), object(), config=cfg, work_dir=tmp_path / "w",
        )
        assert result.harnesses_attempted == 0


class TestRunnerWiring:
    def test_flag_resolution_kwarg(self):
        from clearwing.sourcehunt.runner import SourceHuntRunner

        r = SourceHuntRunner(repo_url="https://example.com/x", fuzz_stage=True)
        assert r._fuzz_stage is True

    def test_flag_resolution_config(self):
        from clearwing.sourcehunt.config import (
            FeatureFlags,
            SourceHuntConfig,
            TargetConfig,
        )
        from clearwing.sourcehunt.runner import SourceHuntRunner

        cfg = SourceHuntConfig(
            target=TargetConfig(repo_url="https://example.com/x"),
            features=FeatureFlags(fuzz_stage=True),
        )
        assert SourceHuntRunner(config=cfg)._fuzz_stage is True

    def test_flag_default_off(self):
        from clearwing.sourcehunt.runner import SourceHuntRunner

        assert SourceHuntRunner(repo_url="https://example.com/x")._fuzz_stage is False

    def test_cli_flag(self):
        import argparse

        from clearwing.ui.commands import sourcehunt as sh_cmd

        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers(dest="command")
        sh_cmd.add_parser(sub)
        args = parser.parse_args(["sourcehunt", "https://example.com/x", "--fuzz-stage"])
        assert args.fuzz_stage is True
