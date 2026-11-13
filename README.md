# aws-efs-audit

[![ci](https://github.com/moveeeax/aws-efs-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/moveeeax/aws-efs-audit/actions/workflows/ci.yml)
[![python](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue)](https://www.python.org/)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Audit EFS file systems for the things the console never puts on one screen: no lifecycle
transition to Infrequent Access, no AWS Backup policy, encryption off, mount targets in a single
availability zone, NFS open to the internet, and provisioned throughput nobody uses.

EFS is usually the storage layer with no policy applied to it at all. Somebody needed a shared
volume, clicked through the wizard, and it has been sitting on Standard storage with one mount
target ever since: the most expensive per-GB storage in the account and a single-AZ dependency
for a multi-AZ service, at the same time.

## What it checks

| Rule | Severity | Trigger |
| --- | --- | --- |
| `no-lifecycle-config` | critical / warn | no `TransitionToIA` rule at all; critical above `--ia-threshold-gb` of Standard data |
| `late-ia-transition` | warn | `TransitionToIA` at 90 days or later while the data is measurably cold |
| `provisioned-throughput-overspend` | warn | provisioned MiB/s more than 2x the measured average |
| `backup-policy-disabled` | critical | `describe_backup_policy` is not `ENABLED` |
| `no-mount-targets` | critical | the file system cannot be mounted from anywhere |
| `single-az-mount-targets` | critical | mount targets in fewer than two availability zones |
| `mount-target-not-available` | critical | a mount target stuck outside the `available` state |
| `uncovered-availability-zones` | warn | zones with subnets in the same VPC but no mount target |
| `encryption-disabled` | critical | `Encrypted` is false, and EFS cannot be encrypted later |
| `nfs-open-to-world` | critical | a mount target security group allows 2049/tcp from `0.0.0.0/0` or `::/0` |
| `access-points-without-policy` | warn | access points exist but no file system policy enforces them |

Each finding carries a `detail` naming the evidence and a `fix` naming the API call. Cost
findings also carry `monthly_saving_usd`.

## Install

```bash
pip install 'git+https://github.com/moveeeax/aws-efs-audit#egg=aws-efs-audit[aws,yaml]'
```

Or from a clone:

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
```

The core package has no dependencies. `boto3` is needed only for live collection (`[aws]`) and
`PyYAML` only for a YAML `--rules` file (`[yaml]`); a JSON rules file works without it.

## Usage

```bash
# one region, live
aws-efs-audit --region eu-central-1

# several regions, non-zero exit when anything is critical
aws-efs-audit --regions eu-central-1,eu-west-1 --fail-on critical

# machine-readable
aws-efs-audit --region eu-central-1 --format json | jq '.filesystems[] | select(.severity=="critical")'

# record once, replay offline as often as you like
aws-efs-audit --region eu-central-1 --dump-json efs.dump.json
aws-efs-audit --from-json efs.dump.json --format markdown
```

Real output against the bundled example payload:

```console
$ aws-efs-audit --from-json examples/prod.json
eu-central-1  fs-0a1b2c3d4e5f60001  (shared-uploads)  400 GB total / 400 GB Standard  [CRIT]
    CRIT AWS Backup policy is not enabled
         describe_backup_policy reports DISABLED; nothing is taking a copy of this volume
         fix: put_backup_policy with Status=ENABLED, or attach the file system to an AWS Backup plan
    CRIT Mount targets in a single availability zone
         only eu-central-1a has a mount target, so every client in another zone depends on that one zone staying up
         fix: create a mount target in at least one more availability zone
    WARN Availability zones with subnets but no mount target
         eu-central-1b, eu-central-1c
         fix: add a mount target in each listed zone; a client there pays cross-AZ traffic today and loses the volume when its own zone is isolated
    CRIT No lifecycle configuration
         400 GB sits in the Standard storage class and nothing ever moves it out (describe_lifecycle_configuration returns no transitions)
         fix: set TransitionToIA=AFTER_30_DAYS via put_lifecycle_configuration; at the configured prices that is about $114/month on the cold portion

...

5 file system(s): 3 critical, 1 warn, 1 clean
15 finding(s): 8 critical, 7 warn
estimated monthly saving if fixed: $1,547.12
```

### Options

| Flag | Meaning |
| --- | --- |
| `--region`, `--regions` | one region or a comma-separated list |
| `--profile` | AWS profile for live collection |
| `--from-json PATH` | replay a recorded payload, zero AWS calls |
| `--dump-json PATH` | write the collected payload for later replay |
| `--rules PATH` | YAML or JSON overrides for any threshold (see `examples/rules.yml`) |
| `--format` | `text` (default), `json`, `markdown` |
| `--fail-on` | `warn`, `critical` or `none` (default) for the exit code |
| `--ia-threshold-gb` | Standard GB above which a missing lifecycle policy is critical |
| `--no-metrics` | skip CloudWatch; throughput rules fall back to size heuristics |

Exit codes: `0` clean, `1` findings at or above `--fail-on`, `2` bad input. A broken
`--from-json` or `--rules` file prints one line to stderr, never a traceback.

### IAM

Read-only, and nothing outside describe calls:

```
elasticfilesystem:DescribeFileSystems
elasticfilesystem:DescribeMountTargets
elasticfilesystem:DescribeMountTargetSecurityGroups
elasticfilesystem:DescribeLifecycleConfiguration
elasticfilesystem:DescribeBackupPolicy
elasticfilesystem:DescribeFileSystemPolicy
elasticfilesystem:DescribeAccessPoints
ec2:DescribeSubnets
ec2:DescribeSecurityGroups
cloudwatch:GetMetricStatistics
```

## How it works

Collection and judgement are separate. `collect.py` turns boto3 responses into plain dicts;
`rules.py` is a list of pure functions over those dicts and never imports boto3. That split is
why `--from-json` can reproduce an entire audit offline, and why every rule in the test suite runs
against a JSON fixture with no credentials and no `moto`.

Coldness is measured where possible rather than assumed. The `MeteredIOBytes` sum from CloudWatch
over 14 days becomes an average MiB/s, normalised per 100 GB of Standard data; below
`cold_mibps_per_100gb` the data is cold. Without metrics (`--no-metrics`, or a file system too new
to have them) the rules fall back to size, which is why `--no-metrics` is explicit rather than
silent.

Zone coverage is scoped to the VPC the existing mount targets live in. A subnet in an unrelated
VPC is not an uncovered zone, and reporting it as one would make the finding noise.

## Thresholds

Everything tunable lives in one frozen dataclass, `model.Thresholds`, and `examples/rules.yml`
lists every key with its default. The price defaults are USD list prices per month; EFS pricing is
regional, so set `price_standard_gb_month`, `price_ia_gb_month` and
`price_provisioned_mibps_month` for your region instead of trusting the defaults. An unknown key
in a rules file is an error, not a silent no-op.

## Development

```bash
pip install -e '.[dev]'
ruff check .
pytest
```

CI runs ruff plus the suite on Python 3.11 and 3.12 on `ubuntu-latest`, then audits
`examples/prod.json` and asserts the exit codes.

## License

MIT
