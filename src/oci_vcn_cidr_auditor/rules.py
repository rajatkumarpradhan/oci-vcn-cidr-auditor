"""Deterministic CIDR rules for a VCN export. Every finding cites its record."""
from __future__ import annotations

import ipaddress
import json
from pathlib import Path

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
UTILIZATION_HEADROOM = 0.8  # CIDR005: subnet space covering >=80% of VCN space


def load_export(path) -> dict:
    data = json.loads(Path(path).read_text())
    if not isinstance(data, dict) or not isinstance(data.get("vcns"), list):
        raise ValueError("export must be an object with a 'vcns' list")
    return data


def _finding(rule, severity, message, citation):
    return {"rule": rule, "severity": severity, "message": message, "citation": citation}


def _parse(cidr_text):
    """Return an ip_network or None when the record is unusable."""
    if not isinstance(cidr_text, str):
        return None
    try:
        return ipaddress.ip_network(cidr_text, strict=True)
    except ValueError:
        return None


def _iter_records(data):
    """Yield (kind, vcn_index, subnet_index_or_None, name, cidr_text)."""
    for vi, vcn in enumerate(data.get("vcns", [])):
        if not isinstance(vcn, dict):
            yield ("bad", vi, None, f"vcns[{vi}]", None)
            continue
        vname = vcn.get("name", f"vcns[{vi}]")
        yield ("vcn", vi, None, vname, vcn.get("cidr"))
        subs = vcn.get("subnets", [])
        if not isinstance(subs, list):
            yield ("bad", vi, -1, f"{vname}.subnets", None)
            continue
        for si, sub in enumerate(subs):
            if not isinstance(sub, dict):
                yield ("bad", vi, si, f"{vname}.subnets[{si}]", None)
                continue
            yield ("subnet", vi, si, f"{vname}/{sub.get('name', si)}", sub.get("cidr"))


def audit_network(data: dict, source: str = "export") -> dict:
    findings = []
    vcns = {}   # vi -> network
    subnets = {}  # (vi, si) -> network

    for kind, vi, si, name, cidr_text in _iter_records(data):
        cite = f"{source}#{'vcn' if si is None else 'subnet'}-{'%s.%s' % (vi, si) if si is not None else vi}"
        net = _parse(cidr_text)
        if net is None:
            findings.append(_finding("CIDR004", "high",
                f"{name}: unusable CIDR record {cidr_text!r} - fix the export, this row was not audited",
                cite))
            continue
        if not isinstance(net, ipaddress.IPv4Network):
            findings.append(_finding("CIDR004", "high",
                f"{name}: IPv6 record {cidr_text} - this auditor covers IPv4 CIDRs only", cite))
            continue
        if si is None:
            vcns[vi] = net
        else:
            subnets[(vi, si)] = net

    # CIDR001: subnet contained in its own VCN
    for (vi, si), net in subnets.items():
        if vi in vcns and not net.subnet_of(vcns[vi]):
            findings.append(_finding("CIDR001", "critical",
                f"subnet {net} is not contained in its VCN {vcns[vi]} - OCI rejects this layout",
                f"{source}#subnet-{vi}.{si}"))

    # CIDR002: overlapping subnets inside one VCN
    for vi in {k[0] for k in subnets}:
        nets = [(k[1], n) for k, n in subnets.items() if k[0] == vi]
        for i in range(len(nets)):
            for j in range(i + 1, len(nets)):
                (si, a), (sj, b) = nets[i], nets[j]
                if a.overlaps(b):
                    findings.append(_finding("CIDR002", "critical",
                        f"subnets {a} and {b} overlap inside the same VCN - OCI rejects this layout",
                        f"{source}#subnet-{vi}.{si}"))

    # CIDR003: overlapping CIDRs across VCNs (blocks local/remote peering)
    vcn_items = sorted(vcns.items())
    for i in range(len(vcn_items)):
        for j in range(i + 1, len(vcn_items)):
            (vi, a), (vj, b) = vcn_items[i], vcn_items[j]
            if a.overlaps(b):
                findings.append(_finding("CIDR003", "high",
                    f"VCN CIDRs {a} and {b} overlap - ordinary peering needs non-overlapping CIDRs; review re-addressing or a separately designed NAT path",
                    f"{source}#vcn-{vi}"))

    # CIDR005: address-space pressure inside a VCN
    for vi, vnet in vcns.items():
        subs = list(ipaddress.collapse_addresses(n for (s_vi, _), n in subnets.items() if s_vi == vi and n.subnet_of(vnet)))
        if not subs:
            continue
        used = sum(n.num_addresses for n in subs)
        ratio = used / vnet.num_addresses
        if ratio >= UTILIZATION_HEADROOM:
            findings.append(_finding("CIDR005", "low",
                f"VCN {vnet}: subnets allocate {ratio:.0%} of the address space - little room for new subnets",
                f"{source}#vcn-{vi}"))

    findings.sort(key=lambda f: (-SEVERITY_ORDER[f["severity"]], f["rule"], f["citation"]))
    summary = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        summary[f["severity"]] += 1
    summary["total"] = len(findings)
    return {"source": source, "vcns_checked": len(vcns), "subnets_checked": len(subnets),
            "findings": findings, "summary": summary}


def worst_severity(report: dict):
    worst = None
    for f in report["findings"]:
        if worst is None or SEVERITY_ORDER[f["severity"]] > SEVERITY_ORDER[worst]:
            worst = f["severity"]
    return worst
