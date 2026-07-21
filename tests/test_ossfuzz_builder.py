"""Tests for OssFuzzBuilder with the docker SDK mocked.

Verifies the $SRC/$OUT/$WORK env contract, read-only host mounts, in-
container source staging, patch application, binary enumeration, and
fail-closed error paths. No real docker daemon is touched.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from clearwing.ossfuzz.builder import BuildConfig, OssFuzzBuilder
from clearwing.ossfuzz.project import OssFuzzProject


@pytest.fixture
def project(tmp_path):
    proj = OssFuzzProject(name="myproj", language="c")
    (tmp_path / "build.sh").write_text("#!/bin/bash -eu\necho building\n")
    return proj


@pytest.fixture
def source_dir(tmp_path):
    src = tmp_path / "checkout"
    src.mkdir()
    (src / "main.c").write_text("int main(void){return 0;}\n")
    return src


def _exec_router(build_exit=0, patch_exit=0, out_listing="fuzz_a\nfuzz_b\n"):
    """Route SandboxContainer exec calls by command content."""

    def router(argv, **kwargs):
        cmd = " ".join(str(a) for a in argv)
        exec_obj = MagicMock()
        exec_obj.output = (b"", b"")
        if "cp -a /src-ro" in cmd:
            exec_obj.exit_code = 0
        elif "apt-get" in cmd:
            exec_obj.exit_code = 0
        elif "patch -p1" in cmd:
            exec_obj.exit_code = patch_exit
            if patch_exit:
                exec_obj.output = (b"patch FAILED", b"")
        elif "chmod" in cmd:
            exec_obj.exit_code = 0
        elif "bash /src/build.sh" in cmd:
            exec_obj.exit_code = build_exit
            exec_obj.output = (b"build output here", b"")
        elif "find /out" in cmd or "ls /out" in cmd:
            exec_obj.exit_code = 0
            exec_obj.output = (out_listing.encode(), b"")
        else:
            exec_obj.exit_code = 0
        return exec_obj

    return router


@pytest.fixture
def mock_docker():
    with patch("docker.from_env") as mock_from_env:
        client = MagicMock()
        container = MagicMock()
        container.id = "buildcontainer1"
        container.short_id = "buildcontain"
        client.containers.run.return_value = container
        mock_from_env.return_value = client
        yield client, container


class TestBuildSuccess:
    def test_build_env_contract(self, mock_docker, project, source_dir, tmp_path):
        client, container = mock_docker
        container.exec_run.side_effect = _exec_router()
        out = tmp_path / "out"

        builder = OssFuzzBuilder(BuildConfig(sanitizer="address"))
        result = builder.build(project, tmp_path, source_dir, out)

        assert result.success, result.error
        assert result.fuzzer_binaries == ["fuzz_a", "fuzz_b"]

        # Container config: OSS-Fuzz base image, no network, ro source mount
        kwargs = client.containers.run.call_args.kwargs
        assert kwargs["image"] == "gcr.io/oss-fuzz-base/base-builder"
        assert kwargs["network_mode"] == "none"
        volumes = kwargs["volumes"]
        assert volumes[str(source_dir.resolve())] == {
            "bind": "/src-ro/myproj",
            "mode": "ro",
        }
        assert volumes[str(out.resolve())] == {"bind": "/out", "mode": "rw"}

        # The OSS-Fuzz env contract
        env = kwargs["environment"]
        assert env["SRC"] == "/src"
        assert env["OUT"] == "/out"
        assert env["WORK"] == "/work"
        assert env["SANITIZER"] == "address"
        assert env["FUZZING_ENGINE"] == "libfuzzer"
        assert env["CC"] == "clang"
        assert env["CXX"] == "clang++"
        assert "-fsanitize=address" in env["CFLAGS"]
        assert "-fsanitize=fuzzer-no-link" in env["CFLAGS"]
        assert "-fsanitize=fuzzer-no-link" in env["CXXFLAGS"]
        assert env["LIB_FUZZING_ENGINE"] == "/usr/lib/libFuzzingEngine.a"
        assert kwargs["working_dir"] == "/src/myproj"

    def test_undefined_sanitizer_flags(self, mock_docker, project, source_dir, tmp_path):
        client, container = mock_docker
        container.exec_run.side_effect = _exec_router()
        builder = OssFuzzBuilder(BuildConfig(sanitizer="undefined"))
        result = builder.build(project, tmp_path, source_dir, tmp_path / "out")
        assert result.success
        env = client.containers.run.call_args.kwargs["environment"]
        assert "-fsanitize=undefined" in env["CFLAGS"]
        assert env["SANITIZER"] == "undefined"

    def test_patch_diff_applied_before_build(self, mock_docker, project, source_dir, tmp_path):
        _, container = mock_docker
        commands: list[str] = []

        def recording_router(argv, **kwargs):
            commands.append(" ".join(str(a) for a in argv))
            return _exec_router()(argv, **kwargs)

        container.exec_run.side_effect = recording_router
        diff = "--- a/main.c\n+++ b/main.c\n@@ -1 +1 @@\n-int main(void){return 0;}\n+int main(void){return 1;}\n"
        result = OssFuzzBuilder().build(
            project,
            tmp_path,
            source_dir,
            tmp_path / "out",
            patch_diff=diff,
        )
        assert result.success, result.error
        patch_idx = next(i for i, c in enumerate(commands) if "patch -p1" in c)
        build_idx = next(i for i, c in enumerate(commands) if "bash /src/build.sh" in c)
        assert patch_idx < build_idx

    def test_apt_packages_switch_network_and_install(
        self, mock_docker, project, source_dir, tmp_path
    ):
        client, container = mock_docker
        commands: list[str] = []

        def recording_router(argv, **kwargs):
            commands.append(" ".join(str(a) for a in argv))
            return _exec_router()(argv, **kwargs)

        container.exec_run.side_effect = recording_router
        cfg = BuildConfig(apt_packages=["zlib1g-dev"])
        result = OssFuzzBuilder(cfg).build(project, tmp_path, source_dir, tmp_path / "out")
        assert result.success, result.error
        assert client.containers.run.call_args.kwargs["network_mode"] == "bridge"
        assert any("apt-get install -y -qq zlib1g-dev" in c for c in commands)


class TestBuildFailures:
    def test_missing_build_sh(self, mock_docker, project, source_dir, tmp_path):
        empty = tmp_path / "emptyproj"
        empty.mkdir()
        result = OssFuzzBuilder().build(project, empty, source_dir, tmp_path / "out")
        assert not result.success
        assert "build.sh not found" in result.error

    def test_missing_source(self, mock_docker, project, tmp_path):
        result = OssFuzzBuilder().build(
            project,
            tmp_path,
            tmp_path / "nope",
            tmp_path / "out",
        )
        assert not result.success
        assert "source dir not found" in result.error

    def test_build_sh_failure(self, mock_docker, project, source_dir, tmp_path):
        _, container = mock_docker
        container.exec_run.side_effect = _exec_router(build_exit=2)
        result = OssFuzzBuilder().build(project, tmp_path, source_dir, tmp_path / "out")
        assert not result.success
        assert "build.sh exited 2" in result.error
        assert "build output here" in result.log

    def test_patch_failure_blocks_build(self, mock_docker, project, source_dir, tmp_path):
        _, container = mock_docker
        container.exec_run.side_effect = _exec_router(patch_exit=1)
        result = OssFuzzBuilder().build(
            project,
            tmp_path,
            source_dir,
            tmp_path / "out",
            patch_diff="--- a/x\n",
        )
        assert not result.success
        assert "patch apply failed" in result.error

    def test_docker_exception_fail_closed(self, mock_docker, project, source_dir, tmp_path):
        client, _ = mock_docker
        client.containers.run.side_effect = RuntimeError("daemon down")
        result = OssFuzzBuilder().build(project, tmp_path, source_dir, tmp_path / "out")
        assert not result.success
        assert "daemon down" in result.error

    def test_bad_sanitizer_rejected(self, mock_docker, project, source_dir, tmp_path):
        result = OssFuzzBuilder(BuildConfig(sanitizer="magic")).build(
            project,
            tmp_path,
            source_dir,
            tmp_path / "out",
        )
        assert not result.success
        assert "unsupported sanitizer" in result.error
