"""Build/inspect artifacts and resolve/install both wheels outside the checkout; never publish."""

import argparse
import configparser
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import zipfile
from email.parser import BytesParser
from pathlib import Path, PurePosixPath

RESOURCES = {
    "gqlsleuth/rules/default_rules.yaml",
    "gqlsleuth/reporting/templates/report.html.j2",
    "gqlsleuth/reporting/templates/report.md.j2",
    "gqlsleuth/discovery/endpoint_candidates.py",
    "gqlsleuth/ai/prompt.py",
    "gqlsleuth/ai/models.py",
}
FORBIDDEN = {
    ".venv",
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    "reports",
    "gqlsleuth-reports",
    "dist",
    "build",
    ".idea",
    ".vscode",
}


def check_names(names: set[str]) -> None:
    for name in names:
        parts = PurePosixPath(name).parts
        assert not (set(parts) & FORBIDDEN), name
        assert not any(p.startswith((".env", ".coverage")) for p in parts), name
        assert not name.endswith((".pyc", ".pyo")), name
        assert not PurePosixPath(name).is_absolute() and ".." not in parts, name


def inspect_wheel(path: Path, project: dict) -> None:
    with zipfile.ZipFile(path) as archive:
        names = set(archive.namelist())
        check_names(names)
        assert names >= RESOURCES, RESOURCES - names
        assert not any(PurePosixPath(n).parts[0] in {"tests", "scripts", "docs"} for n in names)
        metadata_names = [n for n in names if n.endswith(".dist-info/METADATA")]
        assert len(metadata_names) == 1
        metadata = BytesParser().parsebytes(archive.read(metadata_names[0]))
        for key, expected in (
            ("Name", project["name"]),
            ("Version", project["version"]),
            ("Requires-Python", project["requires-python"]),
            ("License-Expression", project["license"]),
            ("Description-Content-Type", "text/markdown"),
        ):
            assert metadata[key] == expected, (key, metadata[key], expected)

        def normalize(value: str) -> str:
            return "".join(value.lower().split()).replace("_", "-")

        assert {normalize(d) for d in metadata.get_all("Requires-Dist", [])} == {
            normalize(d) for d in project["dependencies"]
        }
        assert set(metadata.get_all("Classifier", [])) == set(project["classifiers"])
        assert set(metadata.get_all("Project-URL", [])) == {
            f"{key}, {value}" for key, value in project["urls"].items()
        }
        assert metadata.get_payload().startswith("# GQLSleuth")
        prefix = metadata_names[0].rsplit("/", 1)[0]
        assert prefix + "/licenses/LICENSE" in names
        entry = configparser.ConfigParser()
        entry.read_string(archive.read(prefix + "/entry_points.txt").decode())
        assert dict(entry["console_scripts"]) == project["scripts"]
    print("Wheel metadata/resources passed:", path.name, flush=True)


def inspect_sdist(path: Path) -> str:
    with tarfile.open(path) as archive:
        names = {m.name.rstrip("/") for m in archive.getmembers()}
        check_names(names)
        roots = {PurePosixPath(n).parts[0] for n in names}
        assert len(roots) == 1
        root = roots.pop()
        required = {
            "pyproject.toml",
            "README.md",
            "LICENSE",
            "CHANGELOG.md",
            "docs/RELEASING.md",
            "scripts/check_release_artifacts.py",
            "scripts/installed_smoke.py",
            "src/gqlsleuth/__init__.py",
        }
        required |= {"src/" + r for r in RESOURCES}
        assert {root + "/" + n for n in required} <= names
        assert all(not m.issym() and not m.islnk() for m in archive.getmembers())
    print("Sdist sources/resources passed:", path.name, flush=True)
    return root


def run(command: list[str], cwd: Path, env: dict[str, str]) -> None:
    print("Running:", " ".join(command), flush=True)
    subprocess.run(command, cwd=cwd, env=env, check=True)


def check_release(checkout: Path, work: Path, *, offline: bool) -> None:
    checkout, work = checkout.resolve(), work.resolve()
    assert not work.is_relative_to(checkout), "Artifact work directory must be outside checkout"
    project = tomllib.loads((checkout / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    env = dict(os.environ)
    for key in ("PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV", "UV_PROJECT", "UV_WORKING_DIR"):
        env.pop(key, None)
    env.update(PYTHONNOUSERSITE="1", UV_PYTHON_DOWNLOADS="never")
    if offline:
        env["UV_OFFLINE"] = "1"
    elif env.get("UV_OFFLINE"):
        raise ValueError("Unset UV_OFFLINE or explicitly request --offline")
    uv = shutil.which("uv")
    if not uv:
        raise ValueError("uv is required for release validation")
    dist = work / "dist"
    run([uv, "build", str(checkout), "--out-dir", str(dist)], work, env)
    wheels, sdists = list(dist.glob("*.whl")), list(dist.glob("*.tar.gz"))
    assert len(wheels) == len(sdists) == 1, "Expected one fresh wheel and one sdist"
    inspect_wheel(wheels[0], project)
    root = inspect_sdist(sdists[0])
    extracted = work / "source"
    with tarfile.open(sdists[0]) as archive:
        archive.extractall(extracted, filter="data")
    rebuilt = work / "rebuilt"
    run([uv, "build", str(extracted / root), "--wheel", "--out-dir", str(rebuilt)], work, env)
    rebuilt_wheels = list(rebuilt.glob("*.whl"))
    assert len(rebuilt_wheels) == 1
    inspect_wheel(rebuilt_wheels[0], project)
    for label, wheel in (("wheel", wheels[0]), ("sdist-wheel", rebuilt_wheels[0])):
        venv = work / (label + "-venv")
        run([uv, "venv", "--python", sys.executable, str(venv)], work, env)
        python = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        # No --no-deps, editable installs, source dependency copies, or system site packages.
        run([uv, "pip", "install", "--python", str(python), str(wheel)], work, env)
        run([uv, "pip", "check", "--python", str(python)], work, env)
        smoke_dir = work / (label + "-smoke")
        smoke_dir.mkdir()
        script = smoke_dir / "installed_smoke.py"
        shutil.copyfile(checkout / "scripts/installed_smoke.py", script)
        run(
            [
                str(python),
                "-I",
                str(script),
                "--checkout",
                str(checkout),
                "--version",
                project["version"],
            ],
            smoke_dir,
            env,
        )
    print(
        "Release artifact gate PASSED ("
        + ("offline cache" if offline else "normal resolver")
        + ")."
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--offline", action="store_true", help="Use cached dependencies; fail if missing"
    )
    args = parser.parse_args()
    checkout = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="gqlsleuth-release-") as temporary:
        try:
            check_release(checkout, Path(temporary), offline=args.offline)
        except (AssertionError, ValueError, OSError, subprocess.CalledProcessError) as error:
            print(f"Release artifact gate FAILED: {error}", file=sys.stderr)
            raise SystemExit(1) from None


if __name__ == "__main__":
    main()
