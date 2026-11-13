import json

import pytest

from aws_efs_audit.cli import main


def run(capsys, *argv):
    code = main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_from_json_text_output(capsys, fixtures_dir):
    code, out, err = run(capsys, "--from-json", str(fixtures_dir / "prod.json"))
    assert code == 0
    assert err == ""
    assert "fs-0a1b2c3d4e5f60001" in out
    assert "No lifecycle configuration" in out
    assert "5 file system(s)" in out


def test_json_output_is_machine_readable(capsys, fixtures_dir):
    code, out, _ = run(capsys, "--from-json", str(fixtures_dir / "prod.json"), "--format", "json")
    assert code == 0
    data = json.loads(out)
    assert data["summary"]["file_systems"] == 5
    assert data["summary"]["worst_severity"] == "critical"
    criticals = [f for f in data["filesystems"] if f["severity"] == "critical"]
    assert {f["file_system_id"] for f in criticals} == {
        "fs-0a1b2c3d4e5f60001",
        "fs-0a1b2c3d4e5f60003",
        "fs-0a1b2c3d4e5f60005",
    }


def test_markdown_output_has_a_table(capsys, fixtures_dir):
    code, out, _ = run(capsys, "--from-json", str(fixtures_dir / "prod.json"), "--format", "markdown")
    assert code == 0
    assert out.startswith("# EFS audit")
    assert "| Region | File system |" in out
    assert "backup-policy-disabled" in out


def test_fail_on_critical_exits_one(capsys, fixtures_dir):
    code, _, _ = run(capsys, "--from-json", str(fixtures_dir / "prod.json"), "--fail-on", "critical")
    assert code == 1


def test_fail_on_critical_exits_zero_when_clean(capsys, fixtures_dir):
    code, _, _ = run(capsys, "--from-json", str(fixtures_dir / "clean.json"), "--fail-on", "critical")
    assert code == 0


def test_fail_on_warn_catches_a_warn_only_run(capsys, fixtures_dir, tmp_path):
    payload = json.loads((fixtures_dir / "prod.json").read_text())
    region = payload["regions"]["eu-central-1"]
    region["filesystems"] = [
        fs for fs in region["filesystems"] if fs["FileSystemId"] == "fs-0a1b2c3d4e5f60004"
    ]
    del payload["regions"]["eu-west-1"]
    path = tmp_path / "warn.json"
    path.write_text(json.dumps(payload))
    assert run(capsys, "--from-json", str(path), "--fail-on", "warn")[0] == 1
    assert run(capsys, "--from-json", str(path), "--fail-on", "critical")[0] == 0
    assert run(capsys, "--from-json", str(path))[0] == 0


def test_fail_on_none_is_the_default(capsys, fixtures_dir):
    assert run(capsys, "--from-json", str(fixtures_dir / "prod.json"))[0] == 0


def test_ia_threshold_flag(capsys, fixtures_dir):
    code, out, _ = run(
        capsys,
        "--from-json",
        str(fixtures_dir / "prod.json"),
        "--ia-threshold-gb",
        "1000",
        "--format",
        "json",
    )
    assert code == 0
    uploads = next(
        f for f in json.loads(out)["filesystems"] if f["file_system_id"] == "fs-0a1b2c3d4e5f60001"
    )
    lifecycle = next(f for f in uploads["findings"] if f["rule"] == "no-lifecycle-config")
    assert lifecycle["severity"] == "warn"


def test_negative_threshold_exits_two(capsys, fixtures_dir):
    code, _, err = run(
        capsys, "--from-json", str(fixtures_dir / "prod.json"), "--ia-threshold-gb", "-5"
    )
    assert code == 2
    assert "must not be negative" in err


def test_malformed_payload_exits_two_without_traceback(capsys, fixtures_dir):
    code, _, err = run(capsys, "--from-json", str(fixtures_dir / "malformed.json"))
    assert code == 2
    assert "must be a list" in err
    assert "Traceback" not in err


def test_unparseable_json_exits_two(capsys, fixtures_dir):
    code, _, err = run(capsys, "--from-json", str(fixtures_dir / "not-json.json"))
    assert code == 2
    assert "not valid JSON" in err


def test_missing_file_exits_two(capsys, tmp_path):
    code, _, err = run(capsys, "--from-json", str(tmp_path / "absent.json"))
    assert code == 2
    assert "cannot read" in err


def test_no_region_and_no_payload_exits_two(capsys):
    code, _, err = run(capsys)
    assert code == 2
    assert "--region" in err


def test_from_json_rejects_region_flags(capsys, fixtures_dir):
    code, _, err = run(capsys, "--from-json", str(fixtures_dir / "prod.json"), "--region", "eu-west-1")
    assert code == 2
    assert "drop --region" in err


def test_rules_file_json(capsys, fixtures_dir, tmp_path):
    rules = tmp_path / "rules.json"
    rules.write_text(json.dumps({"ia_threshold_gb": 1000}))
    code, out, _ = run(
        capsys,
        "--from-json",
        str(fixtures_dir / "prod.json"),
        "--rules",
        str(rules),
        "--format",
        "json",
    )
    assert code == 0
    uploads = next(
        f for f in json.loads(out)["filesystems"] if f["file_system_id"] == "fs-0a1b2c3d4e5f60001"
    )
    assert next(f for f in uploads["findings"] if f["rule"] == "no-lifecycle-config")["severity"] == "warn"


def test_rules_file_yaml(capsys, fixtures_dir, tmp_path):
    pytest.importorskip("yaml")
    rules = tmp_path / "rules.yml"
    rules.write_text("min_mount_target_azs: 3\nprice_standard_gb_month: 0.33\n")
    code, _, _ = run(
        capsys, "--from-json", str(fixtures_dir / "prod.json"), "--rules", str(rules), "--fail-on", "critical"
    )
    assert code == 1


def test_broken_rules_file_exits_two(capsys, fixtures_dir, tmp_path):
    rules = tmp_path / "rules.yml"
    rules.write_text("ia_threshold_gb: [1, 2]\n")
    code, _, err = run(capsys, "--from-json", str(fixtures_dir / "prod.json"), "--rules", str(rules))
    assert code == 2
    assert "must be a number" in err


def test_dump_json_round_trips(capsys, fixtures_dir, tmp_path):
    out_path = tmp_path / "copy.json"
    code, _, _ = run(
        capsys, "--from-json", str(fixtures_dir / "prod.json"), "--dump-json", str(out_path)
    )
    assert code == 0
    assert json.loads(out_path.read_text()) == json.loads((fixtures_dir / "prod.json").read_text())


def test_dump_json_to_unwritable_path_exits_two(capsys, fixtures_dir, tmp_path):
    code, _, err = run(
        capsys,
        "--from-json",
        str(fixtures_dir / "prod.json"),
        "--dump-json",
        str(tmp_path / "missing-dir" / "x.json"),
    )
    assert code == 2
    assert "cannot write" in err
