"""Offline artifact regression; resolver-based installation belongs to the release gate."""

import importlib.metadata
import os
import runpy
import shutil
import subprocess
import sys
import tarfile
import tomllib
from pathlib import Path

from typer.testing import CliRunner

import gqlsleuth
from gqlsleuth.cli import app

ROOT = Path(__file__).resolve().parents[2]


def test_version_surfaces_match_project_metadata():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert gqlsleuth.__version__ == importlib.metadata.version("gqlsleuth") == project["version"]
    result = CliRunner().invoke(app, ["version"])
    assert result.exit_code == 0
    assert result.stdout.strip() == f"GQLSleuth {project['version']}"


def test_source_only_version_is_explicitly_unknown(monkeypatch):
    def missing(name):
        raise importlib.metadata.PackageNotFoundError(name)

    monkeypatch.setattr(importlib.metadata, "version", missing)
    module = runpy.run_path(str(ROOT / "src/gqlsleuth/__init__.py"))
    assert module["__version__"] == "0+unknown"


def test_fresh_artifacts_and_sdist_rebuild_offline(tmp_path):
    checker = runpy.run_path(str(ROOT / "scripts/check_release_artifacts.py"))
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    uv = shutil.which("uv")
    assert uv, "Repository artifact tests require uv"
    env = {**os.environ, "UV_OFFLINE": "1", "UV_PYTHON_DOWNLOADS": "never"}
    dist = tmp_path / "dist"
    subprocess.run([uv, "build", str(ROOT), "--out-dir", str(dist)], env=env, check=True)
    wheels, sdists = list(dist.glob("*.whl")), list(dist.glob("*.tar.gz"))
    assert len(wheels) == len(sdists) == 1
    checker["inspect_wheel"](wheels[0], project)
    root = checker["inspect_sdist"](sdists[0])
    source = tmp_path / "source"
    with tarfile.open(sdists[0]) as archive:
        archive.extractall(source, filter="data")
    rebuilt = tmp_path / "rebuilt"
    subprocess.run(
        [uv, "build", str(source / root), "--wheel", "--out-dir", str(rebuilt)],
        cwd=tmp_path,
        env=env,
        check=True,
    )
    checker["inspect_wheel"](next(rebuilt.glob("*.whl")), project)


def test_installed_smoke_guard_blocks_dns_and_connect(tmp_path):
    smoke = runpy.run_path(str(ROOT / "scripts/installed_smoke.py"))
    for attempt in (
        "socket.getaddrinfo('127.0.0.1', 9)",
        "socket.socket().connect(('127.0.0.1', 9))",
    ):
        result = subprocess.run(
            [sys.executable, "-I", "-c", smoke["NETWORK_GUARD"] + "\nimport socket\n" + attempt],
            cwd=tmp_path,
            capture_output=True,
            text=True,
        )
        assert result.returncode != 0
        assert "Installed smoke forbids real network activity" in result.stderr
