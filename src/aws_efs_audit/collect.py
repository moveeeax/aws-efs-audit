"""Live collection from AWS.

Everything here returns plain JSON-serialisable dicts in exactly the shape the
rule engine and ``--from-json`` expect, so a recorded payload replays offline.
"""

from __future__ import annotations

import datetime as _dt
import json
from typing import Any

from .model import ConfigError

PAYLOAD_VERSION = 1


def _iso(value: Any) -> Any:
    if isinstance(value, _dt.datetime):
        return value.astimezone(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return value


def _tags(items) -> dict[str, str]:
    return {t["Key"]: t.get("Value", "") for t in items or [] if "Key" in t}


def _paginate(client, operation: str, key: str, **kwargs):
    paginator = client.get_paginator(operation)
    for page in paginator.paginate(**kwargs):
        for item in page.get(key, []):
            yield item


def _file_system(raw: dict[str, Any]) -> dict[str, Any]:
    size = raw.get("SizeInBytes") or {}
    return {
        "FileSystemId": raw.get("FileSystemId"),
        "Name": raw.get("Name") or _tags(raw.get("Tags")).get("Name", ""),
        "Encrypted": bool(raw.get("Encrypted")),
        "KmsKeyId": raw.get("KmsKeyId"),
        "ThroughputMode": raw.get("ThroughputMode"),
        "ProvisionedThroughputInMibps": raw.get("ProvisionedThroughputInMibps"),
        "PerformanceMode": raw.get("PerformanceMode"),
        "LifeCycleState": raw.get("LifeCycleState"),
        "CreationTime": _iso(raw.get("CreationTime")),
        "SizeInBytes": {
            "Value": size.get("Value"),
            "ValueInIA": size.get("ValueInIA"),
            "ValueInStandard": size.get("ValueInStandard"),
        },
        "Tags": _tags(raw.get("Tags")),
    }


def _mount_target(efs, raw: dict[str, Any]) -> dict[str, Any]:
    mtid = raw.get("MountTargetId")
    groups: list[str] = []
    if mtid:
        try:
            groups = efs.describe_mount_target_security_groups(MountTargetId=mtid).get(
                "SecurityGroups", []
            )
        except Exception:  # noqa: BLE001 - a mount target being created has none yet
            groups = []
    return {
        "MountTargetId": mtid,
        "SubnetId": raw.get("SubnetId"),
        "AvailabilityZoneName": raw.get("AvailabilityZoneName"),
        "IpAddress": raw.get("IpAddress"),
        "LifeCycleState": raw.get("LifeCycleState"),
        "SecurityGroups": groups,
    }


def _lifecycle(efs, fsid: str) -> list[dict[str, Any]]:
    try:
        return efs.describe_lifecycle_configuration(FileSystemId=fsid).get(
            "LifecyclePolicies", []
        )
    except Exception:  # noqa: BLE001
        return []


def _backup_policy(efs, fsid: str) -> str:
    try:
        return (
            efs.describe_backup_policy(FileSystemId=fsid).get("BackupPolicy", {}).get("Status", "")
        )
    except Exception:  # noqa: BLE001 - PolicyNotFound means no policy, i.e. disabled
        return "DISABLED"


def _file_system_policy(efs, fsid: str):
    try:
        return efs.describe_file_system_policy(FileSystemId=fsid).get("Policy")
    except Exception:  # noqa: BLE001
        return None


def _access_points(efs, fsid: str) -> list[dict[str, Any]]:
    try:
        raw = efs.describe_access_points(FileSystemId=fsid).get("AccessPoints", [])
    except Exception:  # noqa: BLE001
        return []
    return [
        {
            "AccessPointId": ap.get("AccessPointId"),
            "Name": ap.get("Name") or _tags(ap.get("Tags")).get("Name", ""),
            "RootDirectory": (ap.get("RootDirectory") or {}).get("Path"),
        }
        for ap in raw
    ]


def _metrics(cloudwatch, fsid: str, days: int = 14) -> dict[str, Any]:
    """Average metered throughput in MiB/s over the window, or {} on failure."""
    end = _dt.datetime.now(_dt.timezone.utc)
    start = end - _dt.timedelta(days=days)
    try:
        resp = cloudwatch.get_metric_statistics(
            Namespace="AWS/EFS",
            MetricName="MeteredIOBytes",
            Dimensions=[{"Name": "FileSystemId", "Value": fsid}],
            StartTime=start,
            EndTime=end,
            Period=3600,
            Statistics=["Sum"],
        )
    except Exception:  # noqa: BLE001
        return {}
    points = [p for p in resp.get("Datapoints", []) if p.get("Sum") is not None]
    if not points:
        return {}
    avg_bytes_per_hour = sum(float(p["Sum"]) for p in points) / len(points)
    mibps = avg_bytes_per_hour / 3600.0 / (1024.0 * 1024.0)
    return {"MeteredIOBytesAvgMibps": round(mibps, 4), "MetricWindowDays": days}


def collect_region(session, region: str, with_metrics: bool = True) -> dict[str, Any]:
    efs = session.client("efs", region_name=region)
    ec2 = session.client("ec2", region_name=region)
    cloudwatch = session.client("cloudwatch", region_name=region) if with_metrics else None

    filesystems = []
    for raw in _paginate(efs, "describe_file_systems", "FileSystems"):
        fs = _file_system(raw)
        fsid = fs["FileSystemId"]
        mts = efs.describe_mount_targets(FileSystemId=fsid).get("MountTargets", [])
        fs["MountTargets"] = [_mount_target(efs, mt) for mt in mts]
        fs["LifecycleConfiguration"] = _lifecycle(efs, fsid)
        fs["BackupPolicy"] = _backup_policy(efs, fsid)
        fs["FileSystemPolicy"] = _file_system_policy(efs, fsid)
        fs["AccessPoints"] = _access_points(efs, fsid)
        fs["Metrics"] = _metrics(cloudwatch, fsid) if cloudwatch is not None else {}
        filesystems.append(fs)

    subnets = [
        {
            "SubnetId": s.get("SubnetId"),
            "AvailabilityZone": s.get("AvailabilityZone"),
            "VpcId": s.get("VpcId"),
            "Tags": _tags(s.get("Tags")),
        }
        for s in _paginate(ec2, "describe_subnets", "Subnets")
    ]

    wanted = {gid for fs in filesystems for mt in fs["MountTargets"] for gid in mt["SecurityGroups"]}
    security_groups = []
    if wanted:
        for g in _paginate(ec2, "describe_security_groups", "SecurityGroups"):
            if g.get("GroupId") in wanted:
                security_groups.append(
                    {
                        "GroupId": g.get("GroupId"),
                        "GroupName": g.get("GroupName"),
                        "IpPermissions": g.get("IpPermissions", []),
                    }
                )

    return {"filesystems": filesystems, "subnets": subnets, "security_groups": security_groups}


def collect(regions: list[str], profile: str | None = None, with_metrics: bool = True) -> dict[str, Any]:
    try:
        import boto3
    except ImportError as exc:  # pragma: no cover - exercised only without boto3
        raise ConfigError(
            "boto3 is required for live collection; install it or use --from-json"
        ) from exc
    session = boto3.Session(profile_name=profile) if profile else boto3.Session()
    return {
        "version": PAYLOAD_VERSION,
        "generated_at": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "regions": {r: collect_region(session, r, with_metrics) for r in regions},
    }


def load_payload(path: str) -> dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc.strerror or exc}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{path} is not valid JSON: {exc.msg} at line {exc.lineno}") from exc
    if not isinstance(payload, dict):
        raise ConfigError(f"{path} must contain a JSON object at the top level")
    return payload
