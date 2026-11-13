import copy

import pytest

from aws_efs_audit.model import GIB, ConfigError, Thresholds
from aws_efs_audit.rules import evaluate

UPLOADS = "fs-0a1b2c3d4e5f60001"
JENKINS = "fs-0a1b2c3d4e5f60002"
LEGACY = "fs-0a1b2c3d4e5f60003"
RENDER = "fs-0a1b2c3d4e5f60004"
DR = "fs-0a1b2c3d4e5f60005"


def by_id(reports):
    return {r.file_system_id: r for r in reports}


def rules_of(report):
    return {f.rule: f for f in report.findings}


def only(payload, fsid, region="eu-central-1"):
    """Narrow a payload down to one file system so a rule is tested alone."""
    narrowed = copy.deepcopy(payload)
    narrowed["regions"] = {region: narrowed["regions"][region]}
    narrowed["regions"][region]["filesystems"] = [
        fs for fs in narrowed["regions"][region]["filesystems"] if fs["FileSystemId"] == fsid
    ]
    return narrowed


# --------------------------------------------------------------------------- #
# acceptance criteria
# --------------------------------------------------------------------------- #


def test_no_lifecycle_on_large_standard_is_critical(prod):
    report = by_id(evaluate(prod))[UPLOADS]
    finding = rules_of(report)["no-lifecycle-config"]
    assert finding.severity == "critical"
    assert "400 GB" in finding.detail
    assert "TransitionToIA=AFTER_30_DAYS" in finding.fix
    # 400 GB moved from Standard ($0.30) to IA ($0.016) with the default prices
    assert finding.monthly_saving_usd == pytest.approx(400 * (0.30 - 0.016), rel=1e-6)
    assert "$114" in finding.fix


def test_small_file_system_without_lifecycle_is_only_warn(prod):
    report = by_id(evaluate(prod))[LEGACY]
    assert rules_of(report)["no-lifecycle-config"].severity == "warn"


def test_ia_threshold_moves_the_line(prod):
    payload = only(prod, LEGACY)
    assert rules_of(evaluate(payload)[0])["no-lifecycle-config"].severity == "warn"
    loose = Thresholds(ia_threshold_gb=10.0)
    assert rules_of(evaluate(payload, loose)[0])["no-lifecycle-config"].severity == "critical"


def test_backup_policy_disabled_is_critical_and_enabled_is_silent(prod):
    reports = by_id(evaluate(prod))
    assert rules_of(reports[UPLOADS])["backup-policy-disabled"].severity == "critical"
    assert "backup-policy-disabled" not in rules_of(reports[JENKINS])


def test_single_az_mount_targets_names_the_zone(prod):
    finding = rules_of(by_id(evaluate(prod))[UPLOADS])["single-az-mount-targets"]
    assert finding.severity == "critical"
    assert "eu-central-1a" in finding.detail


def test_healthy_file_system_has_no_findings(clean):
    reports = evaluate(clean)
    assert len(reports) == 1
    assert reports[0].findings == []
    assert reports[0].severity == "ok"


# --------------------------------------------------------------------------- #
# availability and durability
# --------------------------------------------------------------------------- #


def test_mount_target_not_available_is_critical(prod):
    finding = rules_of(by_id(evaluate(prod))[LEGACY])["mount-target-not-available"]
    assert finding.severity == "critical"
    assert "fsmt-0006=creating" in finding.detail


def test_uncovered_zones_listed_for_same_vpc_only(prod):
    finding = rules_of(by_id(evaluate(prod))[UPLOADS])["uncovered-availability-zones"]
    assert finding.severity == "warn"
    assert finding.detail == "eu-central-1b, eu-central-1c"


def test_fully_covered_file_system_has_no_zone_finding(prod):
    assert "uncovered-availability-zones" not in rules_of(by_id(evaluate(prod))[JENKINS])


def test_no_mount_targets_is_critical(prod):
    payload = only(prod, JENKINS)
    payload["regions"]["eu-central-1"]["filesystems"][0]["MountTargets"] = []
    found = rules_of(evaluate(payload)[0])
    assert found["no-mount-targets"].severity == "critical"
    assert "single-az-mount-targets" not in found


# --------------------------------------------------------------------------- #
# security
# --------------------------------------------------------------------------- #


def test_unencrypted_file_system_is_critical(prod):
    finding = rules_of(by_id(evaluate(prod))[LEGACY])["encryption-disabled"]
    assert finding.severity == "critical"
    assert "DataSync" in finding.fix


def test_world_open_nfs_port_range_is_caught(prod):
    finding = rules_of(by_id(evaluate(prod))[LEGACY])["nfs-open-to-world"]
    assert finding.severity == "critical"
    assert finding.detail == "sg-open"


def test_all_protocols_from_ipv6_world_is_caught(prod):
    payload = only(prod, JENKINS)
    payload["regions"]["eu-central-1"]["filesystems"][0]["MountTargets"][0]["SecurityGroups"] = [
        "sg-open-v6"
    ]
    assert "nfs-open-to-world" in rules_of(evaluate(payload)[0])


def test_client_scoped_security_group_is_not_flagged(prod):
    assert "nfs-open-to-world" not in rules_of(by_id(evaluate(prod))[JENKINS])


def test_access_points_without_policy_warns(prod):
    finding = rules_of(by_id(evaluate(prod))[LEGACY])["access-points-without-policy"]
    assert finding.severity == "warn"
    assert "2 access point(s)" in finding.detail


def test_access_points_with_policy_are_fine(prod):
    payload = only(prod, LEGACY)
    payload["regions"]["eu-central-1"]["filesystems"][0]["FileSystemPolicy"] = '{"Version":"2012-10-17"}'
    assert "access-points-without-policy" not in rules_of(evaluate(payload)[0])


# --------------------------------------------------------------------------- #
# cost
# --------------------------------------------------------------------------- #


def test_over_provisioned_throughput_prints_the_overspend(prod):
    finding = rules_of(by_id(evaluate(prod))[RENDER])["provisioned-throughput-overspend"]
    assert finding.severity == "warn"
    assert finding.monthly_saving_usd == pytest.approx((256 - 18.5) * 6.0)
    assert "$1,425" in finding.fix


def test_provisioned_throughput_in_use_is_not_flagged(prod):
    payload = only(prod, RENDER)
    payload["regions"]["eu-central-1"]["filesystems"][0]["Metrics"]["MeteredIOBytesAvgMibps"] = 200
    assert "provisioned-throughput-overspend" not in rules_of(evaluate(payload)[0])


def test_late_ia_transition_on_cold_data_warns(prod):
    finding = rules_of(by_id(evaluate(prod))[DR])["late-ia-transition"]
    assert finding.severity == "warn"
    assert "AFTER_90_DAYS" in finding.title
    assert "AFTER_30_DAYS" in finding.fix


def test_late_ia_transition_on_hot_data_is_silent(prod):
    payload = copy.deepcopy(prod)
    payload["regions"] = {"eu-west-1": payload["regions"]["eu-west-1"]}
    payload["regions"]["eu-west-1"]["filesystems"][0]["Metrics"]["MeteredIOBytesAvgMibps"] = 90
    assert "late-ia-transition" not in rules_of(evaluate(payload)[0])


def test_standard_bytes_derived_when_absent(prod):
    payload = only(prod, UPLOADS)
    payload["regions"]["eu-central-1"]["filesystems"][0]["SizeInBytes"] = {
        "Value": int(250 * GIB),
        "ValueInIA": int(50 * GIB),
    }
    report = evaluate(payload)[0]
    assert report.standard_gb == pytest.approx(200.0)


# --------------------------------------------------------------------------- #
# thresholds and bad input
# --------------------------------------------------------------------------- #


def test_thresholds_override_from_mapping():
    th = Thresholds.from_mapping({"ia_threshold_gb": 500, "min_mount_target_azs": 3})
    assert th.ia_threshold_gb == 500.0
    assert th.min_mount_target_azs == 3
    assert th.price_standard_gb_month == Thresholds().price_standard_gb_month


def test_unknown_rule_key_is_rejected():
    with pytest.raises(ConfigError) as exc:
        Thresholds.from_mapping({"ia_threshold_tb": 1})
    assert "ia_threshold_tb" in str(exc.value)


def test_non_numeric_rule_value_is_rejected():
    with pytest.raises(ConfigError):
        Thresholds.from_mapping({"ia_threshold_gb": "big"})


def test_min_azs_three_flags_two_zone_file_system(prod):
    payload = only(prod, JENKINS)
    payload["regions"]["eu-central-1"]["filesystems"][0]["MountTargets"].pop()
    th = Thresholds(min_mount_target_azs=3)
    assert "single-az-mount-targets" in rules_of(evaluate(payload, th)[0])


@pytest.mark.parametrize(
    "payload, message",
    [
        ({}, "no 'regions'"),
        ({"regions": {"eu-central-1": {"filesystems": "nope"}}}, "must be a list"),
        ({"regions": {"eu-central-1": {"filesystems": [{}]}}}, "FileSystemId"),
        ({"regions": "eu-central-1"}, "no 'regions'"),
        ({"regions": {"eu-central-1": []}}, "must be an object"),
    ],
)
def test_malformed_payloads_raise_config_error(payload, message):
    with pytest.raises(ConfigError) as exc:
        evaluate(payload)
    assert message in str(exc.value)


def test_every_region_is_evaluated(prod):
    reports = evaluate(prod)
    assert {r.region for r in reports} == {"eu-central-1", "eu-west-1"}
    assert len(reports) == 5
