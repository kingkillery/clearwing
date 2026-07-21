"""Tests for sanitizer report parsing, signature dedup, and Finding conversion."""

from __future__ import annotations

from clearwing.ossfuzz.crashes import (
    CrashDeduplicator,
    crash_signature,
    crash_to_finding,
    cwe_for_crash,
    parse_sanitizer_report,
    severity_for_crash,
)

ASAN_REPORT = """\
==42==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x6020000000f1 at pc 0x55555555aaaa bp 0x7fffffffe000 sp 0x7fffffffdff0
READ of size 16 at 0x6020000000f1 thread T0
    #0 0x55555555aaaa in memcpy /asan/asan_interceptors.cpp:123:3
    #1 0x55555555bbbb in parse_header /src/myproj/src/parse.c:217:9
    #2 0x55555555cccc in main_loop /src/myproj/src/main.c:88:5
    #3 0x55555555dddd in LLVMFuzzerTestOneInput /src/myproj/fuzz.c:20:2
SUMMARY: AddressSanitizer: heap-buffer-overflow /src/myproj/src/parse.c:217:9 in parse_header
"""

UBSAN_REPORT = """\
/src/myproj/src/math.c:54:12: runtime error: signed integer overflow: 2147483647 + 1 cannot be represented in type 'int'
    #0 0xaaaa in add_values /src/myproj/src/math.c:54:12
    #1 0xbbbb in LLVMFuzzerTestOneInput /src/myproj/fuzz.c:12:2
SUMMARY: UndefinedBehaviorSanitizer: signed-integer-overflow /src/myproj/src/math.c:54:12
"""

LIBFUZZER_TIMEOUT = """\
==77==ERROR: libFuzzer: timeout after 31 seconds
    #0 0xaaaa in slow_path /src/myproj/src/slow.c:10:1
"""


class TestParsing:
    def test_asan_report(self):
        crash = parse_sanitizer_report(ASAN_REPORT)
        assert crash.sanitizer == "address"
        assert crash.crash_type == "heap-buffer-overflow"
        assert len(crash.frames) == 4
        top = crash.top_project_frame
        # First /src/ frame is parse_header (frame #0 is the interceptor)
        assert top.function == "parse_header"
        assert top.line == 217

    def test_ubsan_report(self):
        crash = parse_sanitizer_report(UBSAN_REPORT)
        assert crash.crash_type == "signed integer overflow"
        assert crash.top_project_frame.function == "add_values"

    def test_libfuzzer_timeout(self):
        crash = parse_sanitizer_report(LIBFUZZER_TIMEOUT)
        assert crash.sanitizer == "libfuzzer"
        assert "timeout" in crash.crash_type

    def test_empty_report(self):
        crash = parse_sanitizer_report("")
        assert crash.sanitizer == ""
        assert crash.frames == []


class TestSignatures:
    def test_addresses_do_not_change_signature(self):
        """Same bug at different addresses must dedup to one signature."""
        report_a = ASAN_REPORT
        report_b = ASAN_REPORT.replace("0x6020000000f1", "0x603000000042").replace(
            "0x55555555aaaa", "0x555566667777"
        )
        sig_a = crash_signature(parse_sanitizer_report(report_a))
        sig_b = crash_signature(parse_sanitizer_report(report_b))
        assert sig_a == sig_b

    def test_different_crash_types_differ(self):
        sig_a = crash_signature(parse_sanitizer_report(ASAN_REPORT))
        sig_b = crash_signature(parse_sanitizer_report(UBSAN_REPORT))
        assert sig_a != sig_b

    def test_deduplicator(self):
        dedup = CrashDeduplicator()
        crash = parse_sanitizer_report(ASAN_REPORT)
        is_new_a, sig_a = dedup.add(crash)
        is_new_b, sig_b = dedup.add(parse_sanitizer_report(ASAN_REPORT))
        is_new_c, _ = dedup.add(parse_sanitizer_report(UBSAN_REPORT))
        assert is_new_a is True
        assert is_new_b is False
        assert is_new_c is True
        assert sig_a == sig_b
        assert len(dedup) == 2


class TestFindingConversion:
    def test_crash_to_finding_ladder(self):
        crash = parse_sanitizer_report(ASAN_REPORT)
        finding = crash_to_finding(
            crash,
            project_name="myproj",
            fuzzer_name="fuzz_parse",
            poc_path="/results/crashes/fuzz_parse/crash-abcd",
            session_id="sess-1",
        )
        assert finding.evidence_level == "crash_reproduced"
        assert finding.is_strong_evidence
        assert finding.severity == "high"
        assert finding.cwe == "CWE-787"
        assert finding.file == "src/parse.c"
        assert finding.line_number == 217
        assert finding.discovered_by == "ossfuzz_runner"
        assert finding.seeded_from_crash is True
        assert finding.poc == "/results/crashes/fuzz_parse/crash-abcd"
        assert finding.crash_evidence and "heap-buffer-overflow" in finding.crash_evidence
        assert finding.extra["fuzzer"] == "fuzz_parse"
        assert finding.extra["crash_signature"]
        assert finding.hunter_session_id == "sess-1"

    def test_unknown_crash_defaults(self):
        crash = parse_sanitizer_report("some unrecognized output")
        finding = crash_to_finding(crash, project_name="p")
        assert finding.evidence_level == "crash_reproduced"
        assert finding.severity == "low"
        assert finding.cwe == ""
        assert finding.file is None

    def test_severity_and_cwe_helpers(self):
        crash = parse_sanitizer_report(ASAN_REPORT)
        assert severity_for_crash(crash) == "high"
        assert cwe_for_crash(crash) == "CWE-787"

        ubsan = parse_sanitizer_report(UBSAN_REPORT)
        assert severity_for_crash(ubsan) == "medium"
        assert cwe_for_crash(ubsan) == "CWE-190"
