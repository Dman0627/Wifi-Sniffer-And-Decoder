from __future__ import annotations

import json
import sys
import zipfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from wifi_pipeline import __version__
from wifi_pipeline.remote import build_capture_agent_bundle
DIST_DIR = PROJECT_ROOT / "dist"
PORTABLE_NAME = f"wifi-sniffer-and-decoder-{__version__}-portable.zip"

INCLUDE_PATHS = (
    "CHANGELOG.md",
    "GETTING_STARTED.md",
    "RELEASE_CHECKLIST.md",
    "README.md",
    "pyproject.toml",
    "requirements.txt",
    "requirements-dev.txt",
    "install_deps.ps1",
    "install_deps.sh",
    "run_local.sh",
    "run_remote.ps1",
    "run_remote.bat",
    "setup_local.sh",
    "setup_remote.ps1",
    "setup_remote.bat",
    "validate_local.sh",
    "validate_remote.ps1",
    "validate_remote.bat",
    "videopipeline.py",
    "scripts/common.sh",
    "scripts/common.ps1",
    "scripts/build_agent_bundle.py",
    "scripts/release_gate.py",
    "scripts/check.ps1",
    "scripts/check.sh",
    "validation_matrix",
    "wifi_pipeline",
)


def release_members(root: Path = PROJECT_ROOT) -> list[Path]:
    members: list[Path] = []
    for item in INCLUDE_PATHS:
        path = root / item
        if not path.exists():
            continue
        if path.is_dir():
            members.extend(sorted(child for child in path.rglob("*") if child.is_file()))
        else:
            members.append(path)
    return members


def build_portable_zip(root: Path = PROJECT_ROOT, dist_dir: Path = DIST_DIR) -> Path:
    dist_dir.mkdir(parents=True, exist_ok=True)
    zip_path = dist_dir / PORTABLE_NAME
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for member in release_members(root):
            archive.write(member, member.relative_to(root))
    return zip_path


def write_manifest(
    zip_path: Path,
    *,
    agent_bundle_path: Path,
    root: Path = PROJECT_ROOT,
    dist_dir: Path = DIST_DIR,
) -> Path:
    manifest_path = dist_dir / "release-manifest.json"
    payload = {
        "version": __version__,
        "portable_zip": zip_path.name,
        "agent_bundle": agent_bundle_path.name,
        "members": [str(path.relative_to(root)).replace("\\", "/") for path in release_members(root)],
    }
    manifest_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return manifest_path


def main() -> int:
    agent_bundle_path = build_capture_agent_bundle(output_dir=DIST_DIR)
    zip_path = build_portable_zip()
    manifest_path = write_manifest(zip_path, agent_bundle_path=agent_bundle_path)
    print(f"Built capture-agent bundle: {agent_bundle_path}")
    print(f"Built portable archive: {zip_path}")
    print(f"Wrote release manifest: {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
