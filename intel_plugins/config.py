from __future__ import annotations

import json
from pathlib import Path

from intel_core.registry import PluginRegistry
from intel_storage import ensure_workspace_layout

DEFAULT_PLUGIN_SETTINGS_NAME = "plugin_settings.json"
DEFAULT_PLUGIN_PROFILE_NAME = "default"


def default_plugin_profile(
    registry: PluginRegistry,
    *,
    profile_name: str = DEFAULT_PLUGIN_PROFILE_NAME,
) -> dict[str, object]:
    plugins: dict[str, dict[str, object]] = {}
    for manifest in registry.manifests(enabled_only=False):
        registered = registry.get(manifest.name)
        plugins[manifest.name] = {
            "enabled": bool(registered.enabled) if registered is not None else bool(manifest.enabled_by_default),
        }
    return {
        "name": normalize_plugin_profile_name(profile_name) or DEFAULT_PLUGIN_PROFILE_NAME,
        "updated_at": "",
        "plugins": plugins,
    }


def default_plugin_settings(registry: PluginRegistry) -> dict[str, object]:
    default_profile = default_plugin_profile(registry, profile_name=DEFAULT_PLUGIN_PROFILE_NAME)
    return {
        "schema_version": 1,
        "updated_at": "",
        "active_profile": DEFAULT_PLUGIN_PROFILE_NAME,
        "profiles": {
            DEFAULT_PLUGIN_PROFILE_NAME: default_profile,
        },
    }


def normalize_plugin_profile(
    payload: dict[str, object] | None,
    *,
    registry: PluginRegistry,
    profile_name: str,
) -> dict[str, object]:
    source = dict(payload or {})
    base = default_plugin_profile(registry, profile_name=profile_name)
    raw_plugins = dict(source.get("plugins") or {})
    plugins: dict[str, dict[str, object]] = {}
    for manifest in registry.manifests(enabled_only=False):
        registered = registry.get(manifest.name)
        default_enabled = bool(registered.enabled) if registered is not None else bool(manifest.enabled_by_default)
        raw_item = raw_plugins.get(manifest.name)
        if isinstance(raw_item, dict):
            enabled = bool(raw_item.get("enabled", default_enabled))
        elif raw_item in {True, False}:
            enabled = bool(raw_item)
        else:
            enabled = default_enabled
        plugins[manifest.name] = {"enabled": enabled}
    return {
        **base,
        "name": normalize_plugin_profile_name(source.get("name") or profile_name) or DEFAULT_PLUGIN_PROFILE_NAME,
        "updated_at": str(source.get("updated_at") or "").strip(),
        "plugins": plugins,
    }


def normalize_plugin_settings(payload: dict[str, object] | None, *, registry: PluginRegistry) -> dict[str, object]:
    source = dict(payload or {})
    base = default_plugin_settings(registry)
    raw_profiles = dict(source.get("profiles") or {})
    profiles: dict[str, dict[str, object]] = {}
    if DEFAULT_PLUGIN_PROFILE_NAME not in raw_profiles:
        raw_profiles[DEFAULT_PLUGIN_PROFILE_NAME] = base["profiles"][DEFAULT_PLUGIN_PROFILE_NAME]
    for candidate_name, candidate_payload in raw_profiles.items():
        normalized_name = normalize_plugin_profile_name(candidate_name)
        if not normalized_name:
            continue
        profiles[normalized_name] = normalize_plugin_profile(
            candidate_payload if isinstance(candidate_payload, dict) else {},
            registry=registry,
            profile_name=normalized_name,
        )
    if not profiles:
        profiles[DEFAULT_PLUGIN_PROFILE_NAME] = base["profiles"][DEFAULT_PLUGIN_PROFILE_NAME]
    active_profile = normalize_plugin_profile_name(source.get("active_profile") or "")
    if active_profile not in profiles:
        active_profile = DEFAULT_PLUGIN_PROFILE_NAME
    return {
        **base,
        "updated_at": str(source.get("updated_at") or "").strip(),
        "active_profile": active_profile,
        "profiles": profiles,
    }


def load_plugin_settings(output_root: str | Path, *, registry: PluginRegistry) -> dict[str, object]:
    path = plugin_settings_path(output_root)
    if not path.exists():
        return default_plugin_settings(registry)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default_plugin_settings(registry)
    if not isinstance(payload, dict):
        return default_plugin_settings(registry)
    return normalize_plugin_settings(payload, registry=registry)


def persist_plugin_settings(
    output_root: str | Path,
    *,
    registry: PluginRegistry,
    payload: dict[str, object],
) -> dict[str, object]:
    settings = normalize_plugin_settings(payload, registry=registry)
    path = plugin_settings_path(output_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(settings, indent=2), encoding="utf-8")
    return settings


def plugin_settings_path(output_root: str | Path) -> Path:
    root = ensure_workspace_layout(output_root)["root"]
    return (root / "plugins" / DEFAULT_PLUGIN_SETTINGS_NAME).resolve()


def active_plugin_profile(settings: dict[str, object]) -> dict[str, object]:
    normalized = dict(settings or {})
    profile_name = str(normalized.get("active_profile") or DEFAULT_PLUGIN_PROFILE_NAME).strip()
    profiles = dict(normalized.get("profiles") or {})
    payload = dict(profiles.get(profile_name) or {})
    payload.setdefault("name", profile_name)
    payload.setdefault("plugins", {})
    return payload


def plugin_profile_summaries(settings: dict[str, object]) -> tuple[dict[str, object], ...]:
    normalized = dict(settings or {})
    active_name = str(normalized.get("active_profile") or DEFAULT_PLUGIN_PROFILE_NAME).strip()
    rows: list[dict[str, object]] = []
    for name, payload in sorted(dict(normalized.get("profiles") or {}).items()):
        plugins = dict(dict(payload or {}).get("plugins") or {})
        enabled_count = sum(1 for item in plugins.values() if bool(dict(item or {}).get("enabled")))
        disabled_count = sum(1 for item in plugins.values() if not bool(dict(item or {}).get("enabled")))
        rows.append(
            {
                "name": str(name or "").strip(),
                "updated_at": str(dict(payload or {}).get("updated_at") or "").strip(),
                "plugin_count": len(plugins),
                "enabled_count": enabled_count,
                "disabled_count": disabled_count,
                "active": str(name or "").strip() == active_name,
            }
        )
    return tuple(rows)


def normalize_plugin_profile_name(value: object) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return ""
    rows: list[str] = []
    for char in text:
        if char.isalnum() or char in {"-", "_"}:
            rows.append(char)
        elif char in {" ", "."}:
            rows.append("-")
    normalized = "".join(rows).strip("-_")
    return normalized


__all__ = [
    "DEFAULT_PLUGIN_PROFILE_NAME",
    "active_plugin_profile",
    "default_plugin_settings",
    "load_plugin_settings",
    "normalize_plugin_profile_name",
    "persist_plugin_settings",
    "plugin_profile_summaries",
    "plugin_settings_path",
]
