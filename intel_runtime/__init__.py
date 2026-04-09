from __future__ import annotations

from typing import TYPE_CHECKING

__all__ = [
    "DEFAULT_MONITOR_STATUS_NAME",
    "DEFAULT_MONITOR_TUNING_NAME",
    "MonitorRuntime",
    "default_monitor_tuning",
    "default_watch_tuning_profile",
    "load_monitor_tuning",
    "normalize_watch_tuning_profile",
    "update_monitor_tuning",
]


if TYPE_CHECKING:
    from .monitor import DEFAULT_MONITOR_STATUS_NAME, MonitorRuntime
    from .tuning import (
        DEFAULT_MONITOR_TUNING_NAME,
        default_monitor_tuning,
        default_watch_tuning_profile,
        load_monitor_tuning,
        normalize_watch_tuning_profile,
        update_monitor_tuning,
    )


def __getattr__(name: str):
    if name in {"DEFAULT_MONITOR_STATUS_NAME", "MonitorRuntime"}:
        from .monitor import DEFAULT_MONITOR_STATUS_NAME, MonitorRuntime

        values = {
            "DEFAULT_MONITOR_STATUS_NAME": DEFAULT_MONITOR_STATUS_NAME,
            "MonitorRuntime": MonitorRuntime,
        }
        return values[name]
    if name in {
        "DEFAULT_MONITOR_TUNING_NAME",
        "default_monitor_tuning",
        "default_watch_tuning_profile",
        "load_monitor_tuning",
        "normalize_watch_tuning_profile",
        "update_monitor_tuning",
    }:
        from .tuning import (
            DEFAULT_MONITOR_TUNING_NAME,
            default_monitor_tuning,
            default_watch_tuning_profile,
            load_monitor_tuning,
            normalize_watch_tuning_profile,
            update_monitor_tuning,
        )

        values = {
            "DEFAULT_MONITOR_TUNING_NAME": DEFAULT_MONITOR_TUNING_NAME,
            "default_monitor_tuning": default_monitor_tuning,
            "default_watch_tuning_profile": default_watch_tuning_profile,
            "load_monitor_tuning": load_monitor_tuning,
            "normalize_watch_tuning_profile": normalize_watch_tuning_profile,
            "update_monitor_tuning": update_monitor_tuning,
        }
        return values[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
