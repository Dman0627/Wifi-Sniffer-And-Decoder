from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .contracts import PluginManifest

PluginFactory = Callable[[], object]


@dataclass(slots=True, kw_only=True)
class RegisteredPlugin:
    manifest: PluginManifest
    factory: PluginFactory
    enabled: bool = True

    def create(self) -> object:
        return self.factory()


class PluginRegistry:
    def __init__(self) -> None:
        self._plugins: dict[str, RegisteredPlugin] = {}

    def register_plugin(self, plugin: object, *, enabled: bool = True) -> RegisteredPlugin:
        manifest = getattr(plugin, "manifest", None)
        if not isinstance(manifest, PluginManifest):
            raise TypeError("plugin must expose a PluginManifest on .manifest")
        return self.register_factory(plugin.__class__, manifest, enabled=enabled)

    def register_factory(
        self,
        factory: PluginFactory,
        manifest: PluginManifest,
        *,
        enabled: bool = True,
    ) -> RegisteredPlugin:
        name = str(manifest.name or "").strip()
        if not name:
            raise ValueError("plugin manifest name is required")
        if name in self._plugins:
            raise ValueError(f"plugin already registered: {name}")
        registered = RegisteredPlugin(manifest=manifest, factory=factory, enabled=enabled)
        self._plugins[name] = registered
        return registered

    def manifests(
        self,
        *,
        plugin_type: str | None = None,
        enabled_only: bool = False,
    ) -> tuple[PluginManifest, ...]:
        rows = []
        for registered in self._plugins.values():
            if enabled_only and not registered.enabled:
                continue
            if plugin_type and registered.manifest.plugin_type != plugin_type:
                continue
            rows.append(registered.manifest)
        rows.sort(key=lambda item: item.name)
        return tuple(rows)

    def create(self, name: str) -> object:
        key = str(name or "").strip()
        if key not in self._plugins:
            raise KeyError(key)
        return self._plugins[key].create()

    def get(self, name: str) -> RegisteredPlugin | None:
        return self._plugins.get(str(name or "").strip())

    def __contains__(self, name: object) -> bool:
        return str(name or "").strip() in self._plugins

    def __len__(self) -> int:
        return len(self._plugins)
