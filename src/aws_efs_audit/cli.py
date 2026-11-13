"""Command line entry point.

Exit codes: 0 clean, 1 findings at or above --fail-on, 2 bad input.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from dataclasses import replace

from . import __version__
from .collect import collect, load_payload
from .model import ConfigError, Thresholds, at_least
from .report import render, summarise
from .rules import evaluate

FORMATS = ("text", "json", "markdown")
FAIL_ON = ("warn", "critical", "none")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="aws-efs-audit",
        description=(
            "Audit EFS file systems for missing lifecycle policies, disabled backups, "
            "single-AZ mount targets, open NFS and encryption gaps."
        ),
    )
    p.add_argument("--version", action="version", version=f"aws-efs-audit {__version__}")
    p.add_argument("--region", help="single region to audit")
    p.add_argument("--regions", help="comma-separated regions to audit")
    p.add_argument("--profile", help="AWS profile for live collection")
    p.add_argument("--from-json", metavar="PATH", help="replay a recorded payload, no AWS calls")
    p.add_argument("--dump-json", metavar="PATH", help="write the collected payload here")
    p.add_argument("--rules", metavar="PATH", help="YAML or JSON overrides for the thresholds")
    p.add_argument("--format", choices=FORMATS, default="text", dest="fmt")
    p.add_argument("--fail-on", choices=FAIL_ON, default="none")
    p.add_argument(
        "--ia-threshold-gb",
        type=float,
        help="Standard-class GB above which a missing lifecycle policy is critical (default 100)",
    )
    p.add_argument(
        "--no-metrics",
        action="store_true",
        help="skip CloudWatch calls; throughput rules then fall back to size heuristics",
    )
    return p


def load_rules(path: str | None) -> Thresholds:
    if not path:
        return Thresholds()
    try:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc.strerror or exc}") from exc
    data = None
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        try:
            import yaml
        except ImportError as exc:
            raise ConfigError(
                f"{path} is not JSON and PyYAML is not installed to read it as YAML"
            ) from exc
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise ConfigError(f"{path} is not valid YAML: {exc}") from exc
    return Thresholds.from_mapping(data)


def resolve_regions(args: argparse.Namespace) -> list[str]:
    names: list[str] = []
    if args.region:
        names.append(args.region.strip())
    if args.regions:
        names.extend(part.strip() for part in args.regions.split(",") if part.strip())
    out: list[str] = []
    for n in names:
        if n not in out:
            out.append(n)
    return out


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        thresholds = load_rules(args.rules)
        if args.ia_threshold_gb is not None:
            if args.ia_threshold_gb < 0:
                raise ConfigError("--ia-threshold-gb must not be negative")
            thresholds = replace(thresholds, ia_threshold_gb=args.ia_threshold_gb)

        if args.from_json:
            if args.region or args.regions:
                raise ConfigError("--from-json replays a recorded payload; drop --region/--regions")
            payload = load_payload(args.from_json)
        else:
            regions = resolve_regions(args)
            if not regions:
                raise ConfigError("pass --region, --regions or --from-json")
            payload = collect(regions, profile=args.profile, with_metrics=not args.no_metrics)

        if args.dump_json:
            try:
                with open(args.dump_json, "w", encoding="utf-8") as fh:
                    json.dump(payload, fh, indent=2, default=str)
            except OSError as exc:
                raise ConfigError(f"cannot write {args.dump_json}: {exc.strerror or exc}") from exc

        reports = evaluate(payload, thresholds)
    except ConfigError as exc:
        print(f"aws-efs-audit: {exc}", file=sys.stderr)
        return 2

    print(render(reports, args.fmt))

    if args.fail_on == "none":
        return 0
    return 1 if at_least(summarise(reports)["worst_severity"], args.fail_on) else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
