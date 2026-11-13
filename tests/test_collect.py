"""collect.py has no AWS in the tests either: a tiny fake session stands in.

The point is to pin the payload shape, because --from-json replay and every
rule depend on it.
"""

import datetime as dt

from aws_efs_audit.collect import collect_region
from aws_efs_audit.rules import evaluate

GIB = 1024**3


class FakePaginator:
    def __init__(self, pages):
        self._pages = pages

    def paginate(self, **_kwargs):
        return list(self._pages)


class FakeEfs:
    def get_paginator(self, operation):
        assert operation == "describe_file_systems"
        return FakePaginator(
            [
                {
                    "FileSystems": [
                        {
                            "FileSystemId": "fs-1",
                            "Encrypted": False,
                            "ThroughputMode": "bursting",
                            "PerformanceMode": "generalPurpose",
                            "LifeCycleState": "available",
                            "CreationTime": dt.datetime(2024, 5, 1, 12, 0, tzinfo=dt.timezone.utc),
                            "SizeInBytes": {
                                "Value": 300 * GIB,
                                "ValueInIA": 0,
                                "ValueInStandard": 300 * GIB,
                            },
                            "Tags": [
                                {"Key": "Name", "Value": "shared"},
                                {"Key": "team", "Value": "platform"},
                            ],
                        }
                    ]
                }
            ]
        )

    def describe_mount_targets(self, FileSystemId):  # noqa: N803 - boto3 casing
        assert FileSystemId == "fs-1"
        return {
            "MountTargets": [
                {
                    "MountTargetId": "fsmt-1",
                    "SubnetId": "subnet-a",
                    "AvailabilityZoneName": "eu-central-1a",
                    "IpAddress": "10.0.0.5",
                    "LifeCycleState": "available",
                }
            ]
        }

    def describe_mount_target_security_groups(self, MountTargetId):  # noqa: N803
        return {"SecurityGroups": ["sg-1"]}

    def describe_lifecycle_configuration(self, FileSystemId):  # noqa: N803
        return {"LifecyclePolicies": []}

    def describe_backup_policy(self, FileSystemId):  # noqa: N803
        raise RuntimeError("PolicyNotFound")

    def describe_file_system_policy(self, FileSystemId):  # noqa: N803
        raise RuntimeError("FileSystemPolicyNotFound")

    def describe_access_points(self, FileSystemId):  # noqa: N803
        return {"AccessPoints": [{"AccessPointId": "fsap-1", "RootDirectory": {"Path": "/a"}, "Tags": []}]}


class FakeEc2:
    def get_paginator(self, operation):
        if operation == "describe_subnets":
            return FakePaginator(
                [
                    {
                        "Subnets": [
                            {
                                "SubnetId": "subnet-a",
                                "AvailabilityZone": "eu-central-1a",
                                "VpcId": "vpc-1",
                                "Tags": [],
                            },
                            {
                                "SubnetId": "subnet-b",
                                "AvailabilityZone": "eu-central-1b",
                                "VpcId": "vpc-1",
                                "Tags": [],
                            },
                        ]
                    }
                ]
            )
        return FakePaginator(
            [
                {
                    "SecurityGroups": [
                        {"GroupId": "sg-1", "GroupName": "efs", "IpPermissions": []},
                        {"GroupId": "sg-unrelated", "GroupName": "web", "IpPermissions": []},
                    ]
                }
            ]
        )


class FakeCloudWatch:
    def get_metric_statistics(self, **_kwargs):
        # 1 GiB per hour -> about 0.2844 MiB/s
        return {"Datapoints": [{"Sum": float(GIB)}, {"Sum": float(GIB)}]}


class FakeSession:
    def client(self, name, region_name=None):
        return {"efs": FakeEfs(), "ec2": FakeEc2(), "cloudwatch": FakeCloudWatch()}[name]


def test_collect_region_shape():
    region = collect_region(FakeSession(), "eu-central-1")
    assert list(region) == ["filesystems", "subnets", "security_groups"]
    fs = region["filesystems"][0]
    assert fs["Name"] == "shared"
    assert fs["Tags"] == {"Name": "shared", "team": "platform"}
    assert fs["CreationTime"] == "2024-05-01T12:00:00Z"
    assert fs["BackupPolicy"] == "DISABLED"
    assert fs["FileSystemPolicy"] is None
    assert fs["AccessPoints"] == [{"AccessPointId": "fsap-1", "Name": "", "RootDirectory": "/a"}]
    assert fs["MountTargets"][0]["SecurityGroups"] == ["sg-1"]
    assert fs["Metrics"]["MeteredIOBytesAvgMibps"] == 0.2844
    # only the groups actually attached to a mount target are kept
    assert [g["GroupId"] for g in region["security_groups"]] == ["sg-1"]


def test_collect_region_without_metrics():
    region = collect_region(FakeSession(), "eu-central-1", with_metrics=False)
    assert region["filesystems"][0]["Metrics"] == {}


def test_collected_payload_feeds_the_rule_engine():
    payload = {"regions": {"eu-central-1": collect_region(FakeSession(), "eu-central-1")}}
    report = evaluate(payload)[0]
    rules = {f.rule for f in report.findings}
    assert {"encryption-disabled", "backup-policy-disabled", "no-lifecycle-config"} <= rules
    assert report.severity == "critical"
