from __future__ import annotations

import importlib.util
import json
import tarfile
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


def _load_build_agent_bundle_module():
    script_path = Path("scripts/build_agent_bundle.py").resolve()
    spec = importlib.util.spec_from_file_location("build_agent_bundle", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_pyproject_exposes_console_script() -> None:
    data = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))

    assert data["project"]["name"] == "wifi-sniffer-and-decoder"
    assert data["project"]["scripts"]["intelpipeline"] == "intel_api.cli:main"
    assert data["project"]["scripts"]["videopipeline"] == "wifi_pipeline.cli:main"
    assert data["tool"]["setuptools"]["dynamic"]["version"]["attr"] == "wifi_pipeline.__version__"
    assert "intel_*" in data["tool"]["setuptools"]["packages"]["find"]["include"]


def test_project_metadata_points_at_current_repository() -> None:
    data = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    readme = Path("README.md").read_text(encoding="utf-8")

    expected_repo = "https://github.com/Potato4507/Wifi-Sniffer-And-Decoder"

    assert data["project"]["urls"]["Homepage"] == expected_repo
    assert data["project"]["urls"]["Issues"] == f"{expected_repo}/issues"
    assert data["project"]["urls"]["CI"] == f"{expected_repo}/actions/workflows/ci.yml"
    assert data["project"]["urls"]["Changelog"] == f"{expected_repo}/blob/main/CHANGELOG.md"
    assert f"[![CI]({expected_repo}/actions/workflows/ci.yml/badge.svg)]" in readme


def test_dev_installation_uses_pyproject_extras() -> None:
    data = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    requirements_dev = Path("requirements-dev.txt").read_text(encoding="utf-8")
    ci_workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
    release_workflow = Path(".github/workflows/release.yml").read_text(encoding="utf-8")

    assert "build>=1.2" in data["project"]["optional-dependencies"]["dev"]
    assert "pytest>=8" in data["project"]["optional-dependencies"]["dev"]
    assert "-e .[dev]" in requirements_dev
    assert 'python -m pip install ".[dev]"' in ci_workflow
    assert 'python -m pip install ".[dev]"' in release_workflow


def test_build_release_script_creates_portable_zip(tmp_path) -> None:
    build_release = _load_build_release_module()

    zip_path = build_release.build_portable_zip(dist_dir=tmp_path)

    assert zip_path.exists()
    assert __version__ in zip_path.name
    with zipfile.ZipFile(zip_path) as archive:
        members = set(archive.namelist())
    assert "CHANGELOG.md" in members
    assert "GETTING_STARTED.md" in members
    assert "RELEASE_CHECKLIST.md" in members
    assert "README.md" in members
    assert "docs/PLATFORM_WORKFLOW.md" in members
    assert "videopipeline.py" in members
    assert "run_local.sh" in members
    assert "setup_local.sh" in members
    assert "validate_local.sh" in members
    assert "scripts/common.sh" in members
    assert "scripts/common.ps1" in members
    assert "scripts/build_agent_bundle.py" in members
    assert "scripts/release_gate.py" in members
    assert "validation_matrix/README.md" in members
    assert "intel_api/app.py" in members
    assert "intel_api/cli.py" in members
    assert "intel_api/dashboard_render.py" in members
    assert "intel_api/server.py" in members
    assert "intel_collectors/connectors.py" in members
    assert "intel_collectors/filesystem.py" in members
    assert "intel_collectors/logs.py" in members
    assert "intel_collectors/system.py" in members
    assert "intel_correlators/basic.py" in members
    assert "intel_extractors/basic.py" in members
    assert "intel_extractors/external.py" in members
    assert "intel_extractors/pcap.py" in members
    assert "intel_extractors/specialized.py" in members
    assert "intel_extractors/system_artifacts.py" in members
    assert "intel_normalizers/basic.py" in members
    assert "intel_plugins/wifi/plugin.py" in members
    assert "intel_core/records.py" in members
    assert "intel_recovery/basic.py" in members
    assert "intel_runtime/monitor.py" in members
    assert "intel_storage/sqlite_store.py" in members
    assert "intel_storage/workspace.py" in members
    assert "wifi_pipeline/cli.py" in members


def test_build_agent_bundle_script_creates_self_contained_tarball(tmp_path) -> None:
    build_agent_bundle = _load_build_agent_bundle_module()

    bundle_path = build_agent_bundle.build_capture_agent_bundle(output_dir=tmp_path)

    assert bundle_path.exists()
    assert bundle_path.name.endswith("-bundle.tar.gz")
    with tarfile.open(bundle_path, "r:gz") as archive:
        members = set(archive.getnames())
        manifest = json.loads(archive.extractfile("manifest.json").read().decode("utf-8"))
        agent_script = archive.extractfile("bin/wifi-pipeline-agent").read().decode("utf-8")
    assert "install.sh" in members
    assert "bin/wifi-pipeline-agent" in members
    assert "bin/wifi-pipeline-capture" in members
    assert "bin/wifi-pipeline-service" in members
    assert manifest["version"] == __version__
    assert manifest["kind"] == "wifi-pipeline-agent-bundle"
    assert "#!/usr/bin/env bash" in agent_script
    assert 'PROTOCOL="capture-agent/v1"' in agent_script
