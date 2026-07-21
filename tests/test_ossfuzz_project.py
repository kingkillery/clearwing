"""Tests for the OSS-Fuzz project format: model, rendering, scaffold, corpus."""

from __future__ import annotations

import pytest
import yaml

from clearwing.ossfuzz.project import (
    CorpusProject,
    OssFuzzProject,
    load_oss_fuzz_corpus,
    load_project_yaml,
    resolve_oss_fuzz_dir,
    scaffold_project,
)


class TestProjectModel:
    def test_defaults(self):
        p = OssFuzzProject(name="libpng")
        assert p.language == "c"
        assert p.sanitizers == ["address", "undefined"]
        assert p.builder_image == "gcr.io/oss-fuzz-base/base-builder"

    def test_invalid_name_rejected(self):
        with pytest.raises(ValueError, match="invalid OSS-Fuzz project name"):
            OssFuzzProject(name="Bad Name!")

    def test_unknown_sanitizer_rejected(self):
        with pytest.raises(ValueError, match="unknown sanitizers"):
            OssFuzzProject(name="ok", sanitizers=["address", "magic"])

    def test_language_builder_images(self):
        assert OssFuzzProject(name="x", language="rust").builder_image.endswith("base-builder-rust")
        assert OssFuzzProject(name="x", language="python").builder_image.endswith(
            "base-builder-python"
        )

    def test_yaml_round_trip_preserves_unknown_keys(self):
        original = {
            "homepage": "https://example.com",
            "main_repo": "https://github.com/example/proj",
            "language": "c++",
            "sanitizers": ["address"],
            "custom_upstream_field": {"nested": True},
        }
        p = OssFuzzProject.from_yaml_dict("proj", original)
        assert p.language == "c++"
        assert p.extra["custom_upstream_field"] == {"nested": True}
        d = p.to_yaml_dict()
        assert d["custom_upstream_field"] == {"nested": True}
        assert d["language"] == "c++"
        assert d["main_repo"] == "https://github.com/example/proj"

    def test_from_yaml_filters_infra_sanitizers(self):
        p = OssFuzzProject.from_yaml_dict(
            "proj", {"sanitizers": ["address", "coverage", "introspector"]}
        )
        assert p.sanitizers == ["address"]


class TestRendering:
    def test_dockerfile_clone_mode(self):
        p = OssFuzzProject(name="proj", main_repo="https://github.com/a/b")
        df = p.render_dockerfile()
        assert df.startswith("FROM gcr.io/oss-fuzz-base/base-builder")
        assert "git clone --depth 1 https://github.com/a/b $SRC/proj" in df
        assert "WORKDIR $SRC/proj" in df
        assert "COPY build.sh $SRC/build.sh" in df

    def test_dockerfile_local_source_mode(self):
        p = OssFuzzProject(name="proj")
        df = p.render_dockerfile(local_source=True)
        assert "COPY . $SRC/proj" in df
        assert "git clone" not in df

    def test_dockerfile_requires_repo_or_local(self):
        p = OssFuzzProject(name="proj")
        with pytest.raises(ValueError, match="main_repo"):
            p.render_dockerfile()

    def test_build_sh_links_engine(self):
        p = OssFuzzProject(name="proj")
        sh = p.render_build_sh(["fuzz_a.c", "fuzz_b.c"])
        assert sh.startswith("#!/bin/bash -eu")
        assert "$LIB_FUZZING_ENGINE" in sh
        assert "-o $OUT/fuzz_a" in sh
        assert "-o $OUT/fuzz_b" in sh
        assert "$CXX $CXXFLAGS" in sh


class TestScaffold:
    def test_scaffold_writes_triple(self, tmp_path):
        project_dir = scaffold_project(
            name="myproj",
            language="c",
            out_dir=tmp_path,
            main_repo="https://github.com/example/myproj",
            harnesses=["fuzz_one.c"],
        )
        assert project_dir == tmp_path / "myproj"
        assert (project_dir / "project.yaml").is_file()
        assert (project_dir / "Dockerfile").is_file()
        assert (project_dir / "build.sh").is_file()

        data = yaml.safe_load((project_dir / "project.yaml").read_text())
        assert data["language"] == "c"
        assert data["main_repo"] == "https://github.com/example/myproj"

        # Round-trip: the scaffolded triple loads back
        loaded = load_project_yaml(project_dir)
        assert loaded.name == "myproj"
        assert loaded.language == "c"

    def test_scaffold_local_repo_uses_copy(self, tmp_path):
        project_dir = scaffold_project(
            name="localproj",
            language="cpp",
            out_dir=tmp_path,
        )
        df = (project_dir / "Dockerfile").read_text()
        assert "COPY . $SRC/localproj" in df


class TestCorpus:
    def _make_project(self, root, name, language="c", sanitizers=None, with_build_sh=True):
        pdir = root / "projects" / name
        pdir.mkdir(parents=True)
        data = {"language": language, "main_repo": f"https://github.com/x/{name}"}
        if sanitizers:
            data["sanitizers"] = sanitizers
        (pdir / "project.yaml").write_text(yaml.safe_dump(data))
        if with_build_sh:
            (pdir / "build.sh").write_text("#!/bin/bash -eu\n")
        return pdir

    def test_load_corpus(self, tmp_path):
        self._make_project(tmp_path, "alpha")
        self._make_project(tmp_path, "beta", language="rust")
        self._make_project(tmp_path, "nobuild", with_build_sh=False)

        corpus = load_oss_fuzz_corpus(tmp_path)
        names = [c.name for c in corpus]
        assert names == ["alpha", "beta"]  # nobuild filtered, sorted
        assert isinstance(corpus[0], CorpusProject)

    def test_language_filter(self, tmp_path):
        self._make_project(tmp_path, "alpha")
        self._make_project(tmp_path, "beta", language="rust")
        corpus = load_oss_fuzz_corpus(tmp_path, language="rust")
        assert [c.name for c in corpus] == ["beta"]

    def test_sanitizer_filter(self, tmp_path):
        self._make_project(tmp_path, "asan_only", sanitizers=["address"])
        self._make_project(tmp_path, "msan_too", sanitizers=["address", "memory"])
        corpus = load_oss_fuzz_corpus(tmp_path, sanitizer="memory")
        assert [c.name for c in corpus] == ["msan_too"]

    def test_malformed_yaml_skipped(self, tmp_path):
        self._make_project(tmp_path, "good")
        bad = tmp_path / "projects" / "bad"
        bad.mkdir(parents=True)
        (bad / "project.yaml").write_text("- this is a list not a mapping\n")
        (bad / "build.sh").write_text("#!/bin/bash\n")
        corpus = load_oss_fuzz_corpus(tmp_path)
        assert [c.name for c in corpus] == ["good"]

    def test_resolve_prefers_explicit(self, tmp_path, monkeypatch):
        self._make_project(tmp_path, "alpha")
        assert resolve_oss_fuzz_dir(str(tmp_path)) == tmp_path

    def test_resolve_env_var(self, tmp_path, monkeypatch):
        self._make_project(tmp_path, "alpha")
        monkeypatch.setenv("CLEARWING_OSS_FUZZ_DIR", str(tmp_path))
        assert resolve_oss_fuzz_dir() == tmp_path

    def test_resolve_missing_returns_none(self, tmp_path, monkeypatch):
        monkeypatch.delenv("CLEARWING_OSS_FUZZ_DIR", raising=False)
        monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
        assert resolve_oss_fuzz_dir() is None
        assert load_oss_fuzz_corpus(None) == []
