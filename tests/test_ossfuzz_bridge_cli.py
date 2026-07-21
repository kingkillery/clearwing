"""Tests for the ossfuzz→sourcehunt bridge and the CLI command surface."""

from __future__ import annotations

import argparse

from clearwing.ossfuzz.bridge import (
    fuzz_run_to_findings,
    fuzz_run_to_seeded_crashes,
)
from clearwing.ossfuzz.crashes import parse_sanitizer_report
from clearwing.ossfuzz.runner import CrashArtifact, FuzzRunResult

ASAN_TAIL = """\
==42==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x6020000000f1
    #1 0x55555555bbbb in parse_header /src/myproj/src/parse.c:217:9
SUMMARY: AddressSanitizer: heap-buffer-overflow /src/myproj/src/parse.c:217:9
"""


def _run_result() -> FuzzRunResult:
    report = parse_sanitizer_report(ASAN_TAIL)
    new = CrashArtifact(
        fuzzer_name="fuzz_a",
        artifact_name="crash-aaa",
        input_path="/host/crashes/crash-aaa",
        report=report,
        signature="sig-1",
        is_new=True,
    )
    dup = CrashArtifact(
        fuzzer_name="fuzz_a",
        artifact_name="crash-bbb",
        input_path="/host/crashes/crash-bbb",
        report=report,
        signature="sig-1",
        is_new=False,
    )
    return FuzzRunResult(
        fuzzer_name="fuzz_a",
        success=True,
        crashes=[new, dup],
        unique_crash_count=1,
    )


class TestBridge:
    def test_findings_skip_duplicates(self):
        findings = fuzz_run_to_findings(_run_result(), project_name="myproj")
        assert len(findings) == 1
        f = findings[0]
        assert f.evidence_level == "crash_reproduced"
        assert f.file == "src/parse.c"
        assert f.line_number == 217

    def test_findings_include_duplicates_when_asked(self):
        findings = fuzz_run_to_findings(
            _run_result(),
            project_name="myproj",
            include_duplicates=True,
        )
        assert len(findings) == 2

    def test_seeded_crash_shape(self):
        seeds = fuzz_run_to_seeded_crashes(_run_result(), project_name="myproj")
        assert len(seeds) == 1
        seed = seeds[0]
        # Field-for-field compatible with harness_generator.SeededCrash
        assert seed["file"] == "src/parse.c"
        assert seed["target_function"] == "parse_header"
        assert seed["crashed"] is True
        assert "heap-buffer-overflow" in seed["report"]
        assert seed["crash_signature"] == "sig-1"
        assert seed["poc_path"] == "/host/crashes/crash-aaa"


class TestCLI:
    def test_parser_registers_subcommands(self):
        from clearwing.ui.commands import ossfuzz

        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers(dest="command")
        ossfuzz.add_parser(sub)

        args = parser.parse_args(["ossfuzz", "scaffold", "myproj", "--out", "/tmp/x"])
        assert args.command == "ossfuzz"
        assert args.ossfuzz_action == "scaffold"
        assert args.name == "myproj"

        args = parser.parse_args(
            ["ossfuzz", "check-patch", "/p", "--source", "/s", "--diff", "/d", "--crash", "/c"],
        )
        assert args.ossfuzz_action == "check-patch"

        args = parser.parse_args(
            ["ossfuzz", "fuzz", "/out", "--fuzzer", "fuzz_a", "--seconds", "30"],
        )
        assert args.seconds == 30

    def test_scaffold_handler(self, tmp_path):
        from clearwing.ui.commands import ossfuzz

        class FakeConsole:
            def __init__(self):
                self.lines = []

            def print(self, msg, *a, **k):
                self.lines.append(str(msg))

        class FakeCLI:
            def __init__(self):
                self.console = FakeConsole()

        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers(dest="command")
        ossfuzz.add_parser(sub)
        args = parser.parse_args(
            [
                "ossfuzz",
                "scaffold",
                "cliproj",
                "--language",
                "c",
                "--out",
                str(tmp_path),
            ]
        )

        cli = FakeCLI()
        ossfuzz.handle(cli, args)
        assert (tmp_path / "cliproj" / "project.yaml").is_file()
        assert any("Scaffolded" in line for line in cli.console.lines)

    def test_handle_without_action_prints_usage(self):
        from clearwing.ui.commands import ossfuzz

        printed = []

        class FakeConsole:
            def print(self, msg, *a, **k):
                printed.append(str(msg))

        class FakeCLI:
            console = FakeConsole()

        args = argparse.Namespace(ossfuzz_action=None)
        ossfuzz.handle(FakeCLI(), args)
        assert any("Usage" in line for line in printed)
