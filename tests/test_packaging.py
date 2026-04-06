from __future__ import annotations

import importlib.util
import tomllib
import zipfile
from pathlib import Path

from wifi_pipeline import __version__


def _load_build_release_module():
    script_path = Path("scripts/build_release.py").resolve()
    spec = importlib.util.spec_from_file_location("build_release", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_pyproject_exposes_console_script() -> None:
    data = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))

    assert data["project"]["name"] == "wifi-sniffer-and-decoder"
    assert data["project"]["scripts"]["videopipeline"] == "wifi_pipeline.cli:main"
    assert data["tool"]["setuptools"]["dynamic"]["version"]["attr"] == "wifi_pipeline.__version__"


def test_build_release_script_creates_portable_zip(tmp_path) -> None:
    build_release = _load_build_release_module()

    zip_path = build_release.build_portable_zip(dist_dir=tmp_path)

    assert zip_path.exists()
    assert __version__ in zip_path.name
    with zipfile.ZipFile(zip_path) as archive:
        members = set(archive.namelist())
    assert "README.md" in members
    assert "videopipeline.py" in members
    assert "wifi_pipeline/cli.py" in members
