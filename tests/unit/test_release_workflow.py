"""Validate release permissions and staging without running any publishing action."""

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]


def workflow():
    # BaseLoader preserves the YAML 1.2/GitHub key "on" as text, not a YAML 1.1 boolean.
    return yaml.load((ROOT / ".github/workflows/release.yml").read_text(), Loader=yaml.BaseLoader)


def build_code():
    steps = workflow()["jobs"]["build"]["steps"]
    command = next(step["run"] for step in steps if "run" in step)
    assert command.startswith("python - <<'PY'\n") and command.endswith("\nPY\n")
    return compile("\n".join(command.splitlines()[1:-1]), "release-build-step", "exec")


def test_publication_trigger_permissions_and_artifact_handoff():
    release = workflow()
    assert release["on"] == {"release": {"types": ["published"]}}
    assert release["permissions"] == {"contents": "read"}
    assert set(release["jobs"]) == {"build", "publish"}
    build, publish = release["jobs"]["build"], release["jobs"]["publish"]
    assert build["runs-on"] == publish["runs-on"] == "ubuntu-latest"
    assert "permissions" not in build
    assert publish["needs"] == "build"
    assert publish["environment"] == {"name": "pypi"}
    assert publish["permissions"] == {"id-token": "write"}
    checkout = build["steps"][0]
    assert checkout["with"] == {"ref": "${{ github.sha }}", "persist-credentials": "false"}
    setup_python = next(
        s for s in build["steps"] if s.get("uses", "").startswith("actions/setup-python@")
    )
    assert setup_python["with"]["python-version"] == "3.13"
    upload = build["steps"][-1]
    download, publisher = publish["steps"]
    assert upload["uses"].startswith("actions/upload-artifact@")
    assert download["uses"].startswith("actions/download-artifact@")
    assert upload["with"]["name"] == download["with"]["name"]
    assert upload["with"]["path"] == download["with"]["path"] == "dist/"
    assert upload["with"]["if-no-files-found"] == "error"
    assert publisher["uses"].startswith("pypa/gh-action-pypi-publish@")
    assert set(publisher) == {"name", "uses"}
    for job in (build, publish):
        for step in job["steps"]:
            if "uses" in step:
                assert re.fullmatch(r"[\w/-]+@[0-9a-f]{40}", step["uses"])
            assert "secrets." not in str(step)


@pytest.fixture
def release_source(tmp_path, monkeypatch):
    (tmp_path / "pyproject.toml").write_text('[project]\nname="gqlsleuth"\nversion="1.0.0"\n')
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("RELEASE_TAG", "v1.0.0")
    return tmp_path


def test_stages_exact_distributions_only_after_gate_passes(release_source, monkeypatch):
    calls = []
    distributions = {"gqlsleuth-1.0.0.whl": b"validated wheel", "gqlsleuth-1.0.0.tar.gz": b"sdist"}

    def check_release(checkout, work, *, offline):
        assert checkout == release_source and not work.is_relative_to(checkout)
        assert not (checkout / "dist").exists() and offline is False
        (work / "dist").mkdir()
        for name, content in distributions.items():
            (work / "dist" / name).write_bytes(content)
        (work / "dist/.gitignore").write_text("*")
        (work / "other-smoke-output").write_bytes(b"not a distribution")
        calls.append(work)

    monkeypatch.setattr("runpy.run_path", lambda path: {"check_release": check_release})
    exec(build_code(), {})
    assert len(calls) == 1
    assert {p.name: p.read_bytes() for p in (release_source / "dist").iterdir()} == distributions


def test_failed_gate_does_not_stage_distributions(release_source, monkeypatch):
    def check_release(checkout, work, *, offline):
        (work / "dist").mkdir()
        (work / "dist/unvalidated.whl").write_bytes(b"must not be staged")
        raise AssertionError("artifact validation failed")

    monkeypatch.setattr("runpy.run_path", lambda path: {"check_release": check_release})
    with pytest.raises(AssertionError, match="artifact validation failed"):
        exec(build_code(), {})
    assert not (release_source / "dist").exists()


@pytest.mark.parametrize("wrong", ["tag", "name"])
def test_identity_mismatch_stops_before_build(release_source, monkeypatch, wrong):
    if wrong == "tag":
        monkeypatch.setenv("RELEASE_TAG", "v0.0.0")
    else:
        (release_source / "pyproject.toml").write_text('[project]\nname="other"\nversion="1.0.0"\n')

    def unexpected(path):
        pytest.fail("Artifact build must not run on identity mismatch")

    monkeypatch.setattr("runpy.run_path", unexpected)
    with pytest.raises(SystemExit, match="Release tag must match"):
        exec(build_code(), {})
