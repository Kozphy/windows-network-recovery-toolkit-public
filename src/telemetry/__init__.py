"""Windows telemetry readers — Sysmon Event Log, registry target normalization."""

from src.telemetry.registry_targets import (
    INTERNET_SETTINGS_SUFFIX,
    PROXY_VALUE_NAMES,
    is_proxy_registry_target,
    normalize_registry_path,
    proxy_registry_value_name,
)
from src.telemetry.sysmon_reader import SysmonEvent, query_sysmon_events

__all__ = [
    "SysmonEvent",
    "query_sysmon_events",
    "INTERNET_SETTINGS_SUFFIX",
    "PROXY_VALUE_NAMES",
    "is_proxy_registry_target",
    "normalize_registry_path",
    "proxy_registry_value_name",
]
