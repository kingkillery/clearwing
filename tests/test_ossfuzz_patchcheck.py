"""Tests for Buttercup-style patch validation (fail-closed, signature-based).

The builder and runner are faked via monkeypatch so the validation logic —
reproduce → patch → rebuild → confirm — is exercised end to end without
docker.
"""

from __future__ import annotations

import pytest

from clearwing.ossfuzz import patchcheck
from clearwing.ossfuzz.builder import BuildResult
from clearwing.ossfuzz.crashes import parse_sanitizer_report
from clearwing.ossfuzz.project import OssFuzzProject
from clearwing.ossfuzz.runner import ReplayResult


@pytest.fixture
def project():
    return OssFuzzProject(name="myproj", language="c")


@pytest.fixture
def dirs(tmp_path):
    proj_dir = tmp_path / "triple"
    proj_dir.mkdir()
    (proj_dir / "build.sh").write_text("#!/bin/bash -eu\n")
    src = tmp_path / "checkout"
    src.mkdir()
    crash = tmp_path / "crash-input"
    crash.write_bytes(b"POC")
    return proj_dir, src, crash


class FakeBuilder:
    """Scripted builder: succeeds, records patch application."""

    def __init__(self, config=None, fail_patched=False, fail_patch_apply=False):
        self._fail_patched = fail_patched
        self._fail_patch_apply = fail_patch_apply
        self.builds: list[dict] = {}

    def build(self, project, project_dir, source_dir, out_dir, *, patch_diff=None):
        self.builds[str(out_dir)] = {"patch_diff": patch_diff}
        if patch_diff is not None and self._fail_patch_apply:
            return BuildResult(
                success=False,
                out_dir=str(out_dir),
                error="patch apply failed: reject",
            )
        if patch_diff is not None and self._fail_patched:
            return BuildResult(
                success=False,
                out_dir=str(out_dir),
                error="build.sh exited 2",
            )
        return BuildResult(
            success=True,
            out_dir=str(out_dir),
            fuzzer_binaries=["fuzz_a"],
        )


class FakeRunner:
    """Scripted runner: crashes pre-patch, follows `post_crashes` post-patch."""

    def __init__(self, config=None, post_crashes=False, post_signature="sig-other"):
        self._post_crashes = post_crashes
        self._post_signature = post_signature

    def replay(self, out_dir, fuzzer_name, crash_input_path, **kwargs):
        if str(out_dir).endswith("-patched"):
            if self._post_crashes:
                report = parse_sanitizer_report("==1==ERROR: AddressSanitizer: SEGV\n")
                return ReplayResult(
                    crashed=True,
                    exit_code=77,
                    report=report,
                    signature=self._post_signature,
                )
            return ReplayResult(crashed=False, exit_code=0)
        report = parse_sanitizer_report("==1==ERROR: AddressSanitizer: heap-buffer-overflow\n")
        return ReplayResult(crashed=True, exit_code=77, report=report, signature="sig-orig")


def _patch(monkeypatch, builder, runner):
    monkeypatch.setattr(patchcheck, "OssFuzzBuilder", lambda cfg=None: builder)
    monkeypatch.setattr(patchcheck, "FuzzRunner", lambda cfg=None: runner)


class TestValidatePatch:
    def test_validated_when_crash_gone(self, monkeypatch, project, dirs):
        proj_dir, src, crash = dirs
        builder = FakeBuilder()
        _patch(monkeypatch, builder, FakeRunner(post_crashes=False))

        result = patchcheck.validate_patch(
            project,
            proj_dir,
            src,
            "--- a/x\n+++ b/x\n",
            crash,
        )
        assert result.validated is True
        assert result.reproduced_on_vulnerable is True
        assert result.rebuilt is True
        assert result.original_signature == "sig-orig"
        assert result.new_crash_after_patch is False
        # Two builds: unpatched then patched
        assert len(builder.builds) == 2
        patched = [b for b in builder.builds.values() if b["patch_diff"] is not None]
        assert len(patched) == 1

    def test_not_validated_when_same_signature_survives(self, monkeypatch, project, dirs):
        proj_dir, src, crash = dirs
        _patch(
            monkeypatch,
            FakeBuilder(),
            FakeRunner(post_crashes=True, post_signature="sig-orig"),
        )
        result = patchcheck.validate_patch(
            project,
            proj_dir,
            src,
            "diff",
            crash,
        )
        assert result.validated is False
        assert result.new_crash_after_patch is False
        assert "still present" in result.notes

    def test_new_crash_after_patch_flagged(self, monkeypatch, project, dirs):
        proj_dir, src, crash = dirs
        _patch(
            monkeypatch,
            FakeBuilder(),
            FakeRunner(post_crashes=True, post_signature="sig-different"),
        )
        result = patchcheck.validate_patch(
            project,
            proj_dir,
            src,
            "diff",
            crash,
        )
        assert result.validated is False
        assert result.new_crash_after_patch is True
        assert "DIFFERENT crash" in result.notes

    def test_fail_closed_when_no_reproduction(self, monkeypatch, project, dirs):
        proj_dir, src, crash = dirs

        class NoCrashRunner(FakeRunner):
            def replay(self, out_dir, fuzzer_name, crash_input_path, **kwargs):
                return ReplayResult(crashed=False, exit_code=0)

        _patch(monkeypatch, FakeBuilder(), NoCrashRunner())
        result = patchcheck.validate_patch(
            project,
            proj_dir,
            src,
            "diff",
            crash,
        )
        assert result.validated is False
        assert result.reproduced_on_vulnerable is False
        assert "does not reproduce" in result.notes

    def test_fail_closed_when_patched_build_fails(self, monkeypatch, project, dirs):
        proj_dir, src, crash = dirs
        _patch(
            monkeypatch,
            FakeBuilder(fail_patched=True),
            FakeRunner(post_crashes=False),
        )
        result = patchcheck.validate_patch(
            project,
            proj_dir,
            src,
            "diff",
            crash,
        )
        assert result.validated is False
        assert result.rebuilt is False
        assert "patched build failed" in result.notes

    def test_fail_closed_when_patch_rejected(self, monkeypatch, project, dirs):
        proj_dir, src, crash = dirs
        _patch(
            monkeypatch,
            FakeBuilder(fail_patch_apply=True),
            FakeRunner(post_crashes=False),
        )
        result = patchcheck.validate_patch(
            project,
            proj_dir,
            src,
            "diff",
            crash,
        )
        assert result.validated is False
        assert result.patch_applied is False

    def test_missing_crash_input(self, monkeypatch, project, dirs, tmp_path):
        proj_dir, src, _ = dirs
        result = patchcheck.validate_patch(
            project,
            proj_dir,
            src,
            "diff",
            tmp_path / "missing",
        )
        assert result.validated is False
        assert "not found" in result.notes

    def test_reuses_vulnerable_build(self, monkeypatch, project, dirs):
        proj_dir, src, crash = dirs
        builder = FakeBuilder()
        _patch(monkeypatch, builder, FakeRunner(post_crashes=False))
        vuln = BuildResult(
            success=True,
            out_dir=str(src / "out-vuln"),
            fuzzer_binaries=["fuzz_a"],
        )
        result = patchcheck.validate_patch(
            project,
            proj_dir,
            src,
            "diff",
            crash,
            vulnerable_build=vuln,
        )
        assert result.validated is True
        # Only the patched build ran — the vulnerable build was reused
        assert len(builder.builds) == 1
        only = next(iter(builder.builds.values()))
        assert only["patch_diff"] is not None

    def test_multiple_fuzzers_requires_name(self, monkeypatch, project, dirs):
        proj_dir, src, crash = dirs
        _patch(monkeypatch, FakeBuilder(), FakeRunner())
        vuln = BuildResult(
            success=True,
            out_dir=str(src / "out-vuln"),
            fuzzer_binaries=["fuzz_a", "fuzz_b"],
        )
        result = patchcheck.validate_patch(
            project,
            proj_dir,
            src,
            "diff",
            crash,
            vulnerable_build=vuln,
        )
        assert result.validated is False
        assert "cannot determine fuzzer" in result.notes
