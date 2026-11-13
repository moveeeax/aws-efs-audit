"""Shared types: severities, findings and the thresholds every rule reads."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any

GIB = 1024**3

SEVERITY_ORDER = {"ok": 0, "info": 1, "warn": 2, "critical": 3}
SEVERITIES = ("ok", "info", "warn", "critical")


def worst(severities) -> str:
    """Return the highest severity in an iterable, or ``ok`` when it is empty."""
    best = "ok"
    for sev in severities:
        if SEVERITY_ORDER.get(sev, 0) > SEVERITY_ORDER[best]:
            best = sev
    return best


def at_least(sev: str, floor: str) -> bool:
    return SEVERITY_ORDER.get(sev, 0) >= SEVERITY_ORDER[floor]


class ConfigError(Exception):
    """Bad input from the user: a broken payload, an unreadable rules file."""


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    title: str
    detail: str
    fix: str
    monthly_saving_usd: float | None = None

    def to_dict(self) -> dict[str, Any]:
        out = {
            "rule": self.rule,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "fix": self.fix,
        }
        if self.monthly_saving_usd is not None:
            out["monthly_saving_usd"] = round(self.monthly_saving_usd, 2)
        return out


@dataclass(frozen=True)
class Thresholds:
    """Every tunable number in one place so ``--rules`` can override any of it.

    The price defaults are list prices in USD per month and are deliberately
    conservative; EFS pricing is regional, so override them for your region
    instead of trusting these.
    """

    ia_threshold_gb: float = 100.0
    late_transition_days: int = 90
    recommended_transition: str = "AFTER_30_DAYS"
    cold_mibps_per_100gb: float = 0.5
    provisioned_overspend_factor: float = 2.0
    min_mount_target_azs: int = 2
    price_standard_gb_month: float = 0.30
    price_ia_gb_month: float = 0.016
    price_provisioned_mibps_month: float = 6.00
    nfs_port: int = 2049

    @staticmethod
    def from_mapping(data: Any) -> "Thresholds":
        if data is None:
            return Thresholds()
        if not isinstance(data, dict):
            raise ConfigError("rules file must contain a mapping at the top level")
        known = {f.name for f in Thresholds.__dataclass_fields__.values()}
        unknown = sorted(set(data) - known)
        if unknown:
            raise ConfigError(
                "unknown rule keys: " + ", ".join(unknown) + "; known keys: " + ", ".join(sorted(known))
            )
        base = Thresholds()
        typed = {}
        for key, value in data.items():
            current = getattr(base, key)
            if isinstance(current, str):
                typed[key] = str(value)
                continue
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ConfigError(f"rule {key!r} must be a number, got {value!r}")
            typed[key] = int(value) if isinstance(current, int) else float(value)
        return replace(base, **typed)


@dataclass
class FileSystemReport:
    region: str
    file_system_id: str
    name: str
    size_gb: float
    standard_gb: float
    ia_gb: float
    findings: list[Finding] = field(default_factory=list)

    @property
    def severity(self) -> str:
        return worst(f.severity for f in self.findings)

    @property
    def monthly_saving_usd(self) -> float:
        return sum(f.monthly_saving_usd or 0.0 for f in self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "region": self.region,
            "file_system_id": self.file_system_id,
            "name": self.name,
            "size_gb": round(self.size_gb, 2),
            "standard_gb": round(self.standard_gb, 2),
            "ia_gb": round(self.ia_gb, 2),
            "severity": self.severity,
            "monthly_saving_usd": round(self.monthly_saving_usd, 2),
            "findings": [f.to_dict() for f in self.findings],
        }
