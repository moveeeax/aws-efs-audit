"""The rule engine.

Every rule is a plain function over the collected dict for one file system plus
the region inventory it lives in. No boto3 in this module, which is why the
whole thing is testable from JSON fixtures.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

from .model import GIB, ConfigError, FileSystemReport, Finding, Thresholds

WORLD_CIDRS = ("0.0.0.0/0", "::/0")


def _gb(value: Any) -> float:
    try:
        return float(value) / GIB
    except (TypeError, ValueError):
        return 0.0


def _size(fs: dict[str, Any]) -> tuple[float, float, float]:
    size = fs.get("SizeInBytes") or {}
    if not isinstance(size, dict):
        raise ConfigError(f"SizeInBytes must be an object on {fs.get('FileSystemId')!r}")
    total = _gb(size.get("Value"))
    ia = _gb(size.get("ValueInIA"))
    standard = _gb(size.get("ValueInStandard"))
    if not standard and total:
        standard = max(total - ia, 0.0)
    return total, standard, ia


def _mount_targets(fs: dict[str, Any]) -> list[dict[str, Any]]:
    mts = fs.get("MountTargets") or []
    if not isinstance(mts, list):
        raise ConfigError(f"MountTargets must be a list on {fs.get('FileSystemId')!r}")
    return [m for m in mts if isinstance(m, dict)]


def _azs(mount_targets: Iterable[dict[str, Any]]) -> list[str]:
    seen = []
    for mt in mount_targets:
        az = mt.get("AvailabilityZoneName") or mt.get("AvailabilityZoneId")
        if az and az not in seen:
            seen.append(az)
    return sorted(seen)


def _transition_days(rule: dict[str, Any]) -> int | None:
    raw = rule.get("TransitionToIA")
    if not isinstance(raw, str) or not raw.startswith("AFTER_"):
        return None
    head = raw[len("AFTER_") :].split("_")[0]
    return int(head) if head.isdigit() else None


def _cold(fs: dict[str, Any], standard_gb: float, th: Thresholds) -> bool:
    """Is the data cold enough that IA is obviously the right storage class?

    Preferred signal is measured throughput per 100 GB from CloudWatch. When
    metrics are absent we fall back to size: a file system larger than the IA
    threshold is cold enough to be worth a lifecycle policy either way.
    """
    metrics = fs.get("Metrics") or {}
    avg = metrics.get("MeteredIOBytesAvgMibps")
    if isinstance(avg, (int, float)) and standard_gb > 0:
        per_100 = float(avg) / (standard_gb / 100.0)
        return per_100 < th.cold_mibps_per_100gb
    return standard_gb >= th.ia_threshold_gb


# --------------------------------------------------------------------------- #
# cost and lifecycle
# --------------------------------------------------------------------------- #


def rule_lifecycle(fs, region, th: Thresholds) -> list[Finding]:
    total, standard, _ia = _size(fs)
    config = fs.get("LifecycleConfiguration") or []
    if not isinstance(config, list):
        raise ConfigError(f"LifecycleConfiguration must be a list on {fs.get('FileSystemId')!r}")
    transitions = [r for r in config if isinstance(r, dict) and _transition_days(r) is not None]
    saving = standard * (th.price_standard_gb_month - th.price_ia_gb_month)

    if not transitions:
        big = standard > th.ia_threshold_gb
        return [
            Finding(
                rule="no-lifecycle-config",
                severity="critical" if big else "warn",
                title="No lifecycle configuration",
                detail=(
                    f"{standard:.0f} GB sits in the Standard storage class and nothing ever "
                    f"moves it out (describe_lifecycle_configuration returns no transitions)"
                ),
                fix=(
                    f"set TransitionToIA={th.recommended_transition} via "
                    f"put_lifecycle_configuration; at the configured prices that is about "
                    f"${saving:,.0f}/month on the cold portion"
                ),
                monthly_saving_usd=saving,
            )
        ]

    days = min(d for d in (_transition_days(r) for r in transitions) if d is not None)
    if days >= th.late_transition_days and _cold(fs, standard, th):
        return [
            Finding(
                rule="late-ia-transition",
                severity="warn",
                title=f"TransitionToIA is AFTER_{days}_DAYS on cold data",
                detail=(
                    f"{standard:.0f} GB in Standard with no read activity to justify waiting "
                    f"{days} days before the file system moves it"
                ),
                fix=f"tighten TransitionToIA to {th.recommended_transition}",
                monthly_saving_usd=0.0,
            )
        ]
    return []


def rule_provisioned_throughput(fs, region, th: Thresholds) -> list[Finding]:
    if (fs.get("ThroughputMode") or "").lower() != "provisioned":
        return []
    provisioned = fs.get("ProvisionedThroughputInMibps")
    if not isinstance(provisioned, (int, float)) or provisioned <= 0:
        return []
    metrics = fs.get("Metrics") or {}
    avg = metrics.get("MeteredIOBytesAvgMibps")
    if not isinstance(avg, (int, float)):
        return []
    if provisioned <= max(float(avg), 0.0) * th.provisioned_overspend_factor:
        return []
    waste = (float(provisioned) - float(avg)) * th.price_provisioned_mibps_month
    return [
        Finding(
            rule="provisioned-throughput-overspend",
            severity="warn",
            title="Provisioned throughput far above measured average",
            detail=(
                f"provisioned {provisioned:g} MiB/s against a measured average of "
                f"{float(avg):.2f} MiB/s"
            ),
            fix=(
                f"drop to elastic throughput or provision near {max(float(avg) * 1.5, 1.0):.0f} "
                f"MiB/s; the gap costs about ${waste:,.0f}/month"
            ),
            monthly_saving_usd=waste,
        )
    ]


# --------------------------------------------------------------------------- #
# durability and availability
# --------------------------------------------------------------------------- #


def rule_backup_policy(fs, region, th: Thresholds) -> list[Finding]:
    policy = (fs.get("BackupPolicy") or "").upper()
    if policy == "ENABLED":
        return []
    shown = policy or "absent"
    return [
        Finding(
            rule="backup-policy-disabled",
            severity="critical",
            title="AWS Backup policy is not enabled",
            detail=f"describe_backup_policy reports {shown}; nothing is taking a copy of this volume",
            fix="put_backup_policy with Status=ENABLED, or attach the file system to an AWS Backup plan",
        )
    ]


def rule_mount_target_spread(fs, region, th: Thresholds) -> list[Finding]:
    mts = _mount_targets(fs)
    if not mts:
        return [
            Finding(
                rule="no-mount-targets",
                severity="critical",
                title="No mount targets",
                detail="the file system cannot be mounted from anywhere in the VPC",
                fix="create a mount target in every availability zone that runs a client",
            )
        ]
    azs = _azs(mts)
    out = []
    if len(azs) < th.min_mount_target_azs:
        out.append(
            Finding(
                rule="single-az-mount-targets",
                severity="critical",
                title="Mount targets in a single availability zone",
                detail=(
                    f"only {azs[0] if azs else 'an unknown zone'} has a mount target, so every "
                    f"client in another zone depends on that one zone staying up"
                ),
                fix="create a mount target in at least one more availability zone",
            )
        )
    broken = [m for m in mts if (m.get("LifeCycleState") or "").lower() != "available"]
    if broken:
        shown = ", ".join(
            f"{m.get('MountTargetId', '?')}={m.get('LifeCycleState', 'unknown')}" for m in broken
        )
        out.append(
            Finding(
                rule="mount-target-not-available",
                severity="critical",
                title="Mount target not in the available state",
                detail=shown,
                fix="delete and recreate the mount target, or free the subnet IP it is waiting for",
            )
        )
    return out


def rule_uncovered_azs(fs, region, th: Thresholds) -> list[Finding]:
    """Zones that hold subnets in the same VPC but no mount target."""
    mts = _mount_targets(fs)
    if not mts:
        return []
    covered = set(_azs(mts))
    mt_subnets = {m.get("SubnetId") for m in mts}
    subnets = [s for s in (region.get("subnets") or []) if isinstance(s, dict)]
    vpcs = {s.get("VpcId") for s in subnets if s.get("SubnetId") in mt_subnets}
    uncovered = sorted(
        {
            s.get("AvailabilityZone")
            for s in subnets
            if s.get("VpcId") in vpcs and s.get("AvailabilityZone") not in covered
        }
        - {None}
    )
    if not uncovered:
        return []
    return [
        Finding(
            rule="uncovered-availability-zones",
            severity="warn",
            title="Availability zones with subnets but no mount target",
            detail=", ".join(uncovered),
            fix=(
                "add a mount target in each listed zone; a client there pays cross-AZ traffic "
                "today and loses the volume when its own zone is isolated"
            ),
        )
    ]


# --------------------------------------------------------------------------- #
# security
# --------------------------------------------------------------------------- #


def rule_encryption(fs, region, th: Thresholds) -> list[Finding]:
    if fs.get("Encrypted"):
        return []
    return [
        Finding(
            rule="encryption-disabled",
            severity="critical",
            title="Encryption at rest is off",
            detail="Encrypted is false and EFS cannot be encrypted after creation",
            fix=(
                "create an encrypted file system and copy the data across with DataSync; "
                "there is no in-place migration"
            ),
        )
    ]


def _permits_world_nfs(group: dict[str, Any], port: int) -> bool:
    for perm in group.get("IpPermissions") or []:
        if not isinstance(perm, dict):
            continue
        proto = str(perm.get("IpProtocol", "")).lower()
        if proto not in ("tcp", "-1"):
            continue
        low = perm.get("FromPort")
        high = perm.get("ToPort")
        if proto == "tcp":
            if not isinstance(low, int) or not isinstance(high, int):
                continue
            if not (low <= port <= high):
                continue
        open_v4 = any(r.get("CidrIp") in WORLD_CIDRS for r in perm.get("IpRanges") or [])
        open_v6 = any(r.get("CidrIpv6") in WORLD_CIDRS for r in perm.get("Ipv6Ranges") or [])
        if open_v4 or open_v6:
            return True
    return False


def rule_open_nfs(fs, region, th: Thresholds) -> list[Finding]:
    groups = {
        g.get("GroupId"): g
        for g in (region.get("security_groups") or [])
        if isinstance(g, dict)
    }
    offenders = []
    for mt in _mount_targets(fs):
        for gid in mt.get("SecurityGroups") or []:
            group = groups.get(gid)
            if group and _permits_world_nfs(group, th.nfs_port) and gid not in offenders:
                offenders.append(gid)
    if not offenders:
        return []
    return [
        Finding(
            rule="nfs-open-to-world",
            severity="critical",
            title=f"Mount target security group allows {th.nfs_port}/tcp from the internet",
            detail=", ".join(offenders),
            fix=f"restrict {th.nfs_port}/tcp to the client security groups that mount the volume",
        )
    ]


def rule_policy_with_access_points(fs, region, th: Thresholds) -> list[Finding]:
    access_points = fs.get("AccessPoints") or []
    if not access_points or fs.get("FileSystemPolicy"):
        return []
    return [
        Finding(
            rule="access-points-without-policy",
            severity="warn",
            title="Access points exist but no file system policy enforces them",
            detail=(
                f"{len(access_points)} access point(s) and an empty file system policy, so a "
                f"client can still mount the root of the volume directly"
            ),
            fix=(
                "attach a file system policy denying mounts without "
                "elasticfilesystem:AccessPointArn"
            ),
        )
    ]


RULES: tuple[Callable[..., list[Finding]], ...] = (
    rule_encryption,
    rule_backup_policy,
    rule_mount_target_spread,
    rule_uncovered_azs,
    rule_open_nfs,
    rule_policy_with_access_points,
    rule_lifecycle,
    rule_provisioned_throughput,
)


def evaluate_file_system(fs: dict[str, Any], region_name: str, region: dict[str, Any],
                         th: Thresholds) -> FileSystemReport:
    if not isinstance(fs, dict):
        raise ConfigError("every entry in filesystems must be an object")
    fsid = fs.get("FileSystemId")
    if not fsid:
        raise ConfigError("a file system is missing FileSystemId")
    total, standard, ia = _size(fs)
    report = FileSystemReport(
        region=region_name,
        file_system_id=fsid,
        name=fs.get("Name") or (fs.get("Tags") or {}).get("Name") or "",
        size_gb=total,
        standard_gb=standard,
        ia_gb=ia,
    )
    for rule in RULES:
        report.findings.extend(rule(fs, region, th))
    return report


def evaluate(payload: dict[str, Any], th: Thresholds | None = None) -> list[FileSystemReport]:
    """Run every rule over a collected payload and return one report per file system."""
    th = th or Thresholds()
    if not isinstance(payload, dict):
        raise ConfigError("payload must be a JSON object")
    regions = payload.get("regions")
    if not isinstance(regions, dict) or not regions:
        raise ConfigError("payload has no 'regions' object")
    reports = []
    for region_name in sorted(regions):
        region = regions[region_name]
        if not isinstance(region, dict):
            raise ConfigError(f"region {region_name!r} must be an object")
        filesystems = region.get("filesystems")
        if filesystems is None:
            filesystems = []
        if not isinstance(filesystems, list):
            raise ConfigError(f"region {region_name!r}: filesystems must be a list")
        for fs in filesystems:
            reports.append(evaluate_file_system(fs, region_name, region, th))
    return reports
