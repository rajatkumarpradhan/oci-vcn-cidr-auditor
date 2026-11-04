"""CLI: audit a VCN export and gate CI on severity."""
import argparse
import json
import sys
from pathlib import Path

from .rules import audit_network, load_export, worst_severity


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="oci-vcn-cidr-auditor",
        description="Audit an OCI VCN/subnet export for CIDR containment, overlap and headroom")
    parser.add_argument("export", help="path to the VCN export JSON")
    parser.add_argument("--output", help="write the JSON report here instead of stdout")
    parser.add_argument("--fail-on", choices=["low", "medium", "high", "critical"],
        help="exit 2 when a finding at/above this severity exists")
    args = parser.parse_args(argv)

    try:
        data = load_export(args.export)
    except (OSError, ValueError) as exc:
        print(f"error: cannot load export: {exc}", file=sys.stderr)
        return 1

    report = audit_network(data, Path(args.export).name)
    out = json.dumps(report, indent=2)
    if args.output:
        Path(args.output).write_text(out + "\n")
        print(f"report written to {args.output}")
    else:
        print(out)

    worst = worst_severity(report)
    if args.fail_on and worst:
        order = ["low", "medium", "high", "critical"]
        if order.index(worst) >= order.index(args.fail_on):
            print(f"gate: worst finding '{worst}' >= --fail-on '{args.fail_on}'", file=sys.stderr)
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
