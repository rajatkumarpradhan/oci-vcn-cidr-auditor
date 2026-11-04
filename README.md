# OCI VCN CIDR auditor

Catch address-plan mistakes before a network change. A deterministic, IPv4-only tool
for a simplified static export, with record citations and a CI severity gate.

## Run

```sh
python -m pip install -e .
python -m unittest discover -s tests -v
python scripts/demo.py
oci-vcn-cidr-auditor examples/network.json --fail-on high
# expected exit 2 for the seeded bad layout; 0 means no finding at the chosen level
```

The demo detects five seeded findings, then audits a corrected layout with zero findings.
`--output report.json` saves the report. Load/JSON errors exit 1.

## Rules

- CIDR001 critical: subnet outside its parent VCN.
- CIDR002 critical: overlapping subnets within a VCN.
- CIDR003 high: overlapping VCNs need review before ordinary peering.
- CIDR004 high: invalid, host-bit-set, unsupported IPv6 or malformed records.
- CIDR005 low: contained subnet union covers >=80% of VCN space. Uses a union,
  so overlapping and out-of-VCN subnets cannot inflate the pressure calculation.

## Input and scope

See examples/network.json. Each VCN has one `cidr` and a `subnets` list. Each subnet
has a `cidr`. This is a purpose-built input schema, not raw OCI SDK output.
All VCN pairs are checked, regardless of intended connectivity. CIDR003 is therefore
advisory, not proof that unrelated VCNs are misconfigured. Multi-CIDR VCNs, IPv6,
NAT, route tables, IAM, actual IP utilization and reserved addresses are out of scope.
80% is a project convention, not an Oracle default.

Oracle's ordinary remote-peering guidance requires non-overlapping CIDRs:
https://docs.oracle.com/en-us/iaas/Content/Network/Tasks/scenario_e.htm
A separate NAT design can support overlapping networks, so the tool does not claim
that overlapping VCNs can never communicate.

Offline synthetic fixtures only. No OCI API, deployment, tenancy access or spend.
