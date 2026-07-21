"""Tests for FuzzRunner with the docker SDK mocked.

Covers fuzz command construction, artifact collection with signature
dedup, host-side artifact persistence, the exit-code fallback path, and
single-input replay. No real docker daemon is touched.
"""

from __future__ import annotations

import io
import tarfile
from unittest.mock import MagicMock, patch

import pytest

from clearwing.ossfuzz.runner import (
    FuzzConfig,
    FuzzRunner,
    _parse_runs_executed,
)

ASAN_TAIL = """\
==42==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x6020000000f1
    #0 0x55555555aaaa in memcpy /asan/asan_interceptors.cpp:123:3
    #1 0x55555555bbbb in parse_header /src/myproj/src/parse.c:217:9
SUMMARY: AddressSanitizer: heap-buffer-overflow /src/myproj/src/parse.c:217:9
"""

FUZZ_STATS = """\
INFO: Running with entropic power schedule (0xFF, 100).
#12345	DONE   cov: 42 ft: 100 corp: 12/34b exec/s: 411 lim: 4096
stat::number_of_executed_units: 12345
"""


def _tar_bytes(name: str, data: bytes) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        info = tarfile.TarInfo(name=name)
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


@pytest.fixture
def out_dir(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    (out / "fuzz_a").write_bytes(b"\x7fELF fake binary")
    return out


@pytest.fixture
def mock_docker():
    with patch("docker.from_env") as mock_from_env:
        client = MagicMock()
        container = MagicMock()
        container.id = "fuzzcontainer1"
        container.short_id = "fuzzcontain"
        client.containers.run.return_value = container
        mock_from_env.return_value = client
        yield client, container


def _fuzz_router(artifact_names=("crash-abc123",), crash_data=b"POC-DATA"):
    """Router for a fuzz run that produced one artifact."""

    def router(argv, **kwargs):
        cmd = " ".join(str(a) for a in argv)
        exec_obj = MagicMock()
        if "-max_total_time=" in cmd:
            exec_obj.exit_code = 77
            exec_obj.output = ((FUZZ_STATS + ASAN_TAIL).encode(), b"")
        elif "ls /artifacts" in cmd:
            exec_obj.exit_code = 0
            exec_obj.output = ("\n".join(artifact_names).encode(), b"")
        elif "/out/fuzz_a /artifacts/" in cmd:
            # Confirmation replay inside the container
            exec_obj.exit_code = 77
            exec_obj.output = (ASAN_TAIL.encode(), b"")
        else:
            exec_obj.exit_code = 0
            exec_obj.output = (b"", b"")
        return exec_obj

    return router


class TestFuzzRun:
    def test_collects_and_dedups_artifacts(self, mock_docker, out_dir, tmp_path):
        client, container = mock_docker
        container.exec_run.side_effect = _fuzz_router(
            artifact_names=("crash-aaa111", "crash-bbb222"),
        )
        container.get_archive.side_effect = lambda path: (
            iter([_tar_bytes(path.rsplit("/", 1)[-1], b"POC-DATA")]),
            {},
        )

        crashes_dir = tmp_path / "crashes"
        runner = FuzzRunner(FuzzConfig(crashes_dir=str(crashes_dir)))
        result = runner.fuzz(out_dir, "fuzz_a")

        assert result.success, result.error
        assert result.runs_executed == 12345
        assert len(result.crashes) == 2
        # Both artifacts report the SAME crash → one unique, one dup
        assert result.unique_crash_count == 1
        assert result.crashes[0].is_new is True
        assert result.crashes[1].is_new is False
        assert result.crashes[0].report.crash_type == "heap-buffer-overflow"

        # Artifacts persisted to the host crashes dir
        saved = crashes_dir / "fuzz_a" / "crash-aaa111"
        assert saved.is_file()
        assert saved.read_bytes() == b"POC-DATA"

        # Sandbox hardened: no network, $OUT mounted ro, crashes dir rw
        kwargs = client.containers.run.call_args.kwargs
        assert kwargs["network_mode"] == "none"
        volumes = kwargs["volumes"]
        assert volumes[str(out_dir.resolve())] == {"bind": "/out", "mode": "ro"}
        assert volumes[str(crashes_dir.resolve())] == {
            "bind": "/artifacts",
            "mode": "rw",
        }

    def test_fuzz_command_args(self, mock_docker, out_dir, tmp_path):
        _, container = mock_docker
        commands: list[str] = []

        def recording(argv, **kwargs):
            commands.append(" ".join(str(a) for a in argv))
            return _fuzz_router(artifact_names=())(argv, **kwargs)

        container.exec_run.side_effect = recording
        runner = FuzzRunner(FuzzConfig(max_total_time_seconds=120, rss_limit_mb=1024))
        result = runner.fuzz(out_dir, "fuzz_a")
        assert result.success
        fuzz_cmd = next(c for c in commands if "-max_total_time=" in c)
        assert "/out/fuzz_a" in fuzz_cmd
        assert "-max_total_time=120" in fuzz_cmd
        assert "-rss_limit_mb=1024" in fuzz_cmd
        assert "-artifact_prefix=/artifacts/" in fuzz_cmd

    def test_exit_code_fallback_without_artifact(self, mock_docker, out_dir):
        """Crash-class exit code with no artifact still yields a crash record."""
        _, container = mock_docker
        container.exec_run.side_effect = _fuzz_router(artifact_names=())
        result = FuzzRunner().fuzz(out_dir, "fuzz_a")
        assert result.success
        assert len(result.crashes) == 1
        assert result.crashes[0].exit_code == 77
        assert result.crashes[0].report.crash_type == "heap-buffer-overflow"

    def test_missing_binary(self, mock_docker, out_dir):
        result = FuzzRunner().fuzz(out_dir, "nonexistent")
        assert not result.success
        assert "not found" in result.error

    def test_docker_exception_fail_closed(self, mock_docker, out_dir):
        client, _ = mock_docker
        client.containers.run.side_effect = RuntimeError("daemon down")
        result = FuzzRunner().fuzz(out_dir, "fuzz_a")
        assert not result.success
        assert "daemon down" in result.error


class TestReplay:
    def test_replay_crash_signature(self, mock_docker, out_dir, tmp_path):
        _, container = mock_docker
        crash_input = tmp_path / "crash-abc123"
        crash_input.write_bytes(b"POC")

        def router(argv, **kwargs):
            exec_obj = MagicMock()
            exec_obj.exit_code = 77
            exec_obj.output = (ASAN_TAIL.encode(), b"")
            return exec_obj

        container.exec_run.side_effect = router
        result = FuzzRunner().replay(out_dir, "fuzz_a", crash_input)
        assert result.crashed
        assert result.exit_code == 77
        assert result.report.crash_type == "heap-buffer-overflow"
        assert result.signature

    def test_replay_clean(self, mock_docker, out_dir, tmp_path):
        _, container = mock_docker
        crash_input = tmp_path / "ok-input"
        crash_input.write_bytes(b"fine")

        def router(argv, **kwargs):
            exec_obj = MagicMock()
            exec_obj.exit_code = 0
            exec_obj.output = (b"INFO: done\n", b"")
            return exec_obj

        container.exec_run.side_effect = router
        result = FuzzRunner().replay(out_dir, "fuzz_a", crash_input)
        assert not result.crashed
        assert result.signature == ""

    def test_replay_missing_input(self, mock_docker, out_dir, tmp_path):
        result = FuzzRunner().replay(out_dir, "fuzz_a", tmp_path / "nope")
        assert not result.crashed
        assert "not found" in result.error


class TestStatsParsing:
    def test_done_line(self):
        assert _parse_runs_executed(FUZZ_STATS) == 12345

    def test_stat_line(self):
        assert _parse_runs_executed("stat::number_of_executed_units: 777\n") == 777

    def test_no_stats(self):
        assert _parse_runs_executed("nothing here") == 0
