#!/usr/bin/env python3
"""
Structured report exporter for adenum.

Reads findings.jsonl (one JSON object per finding, written by add_finding) and
emits three machine-readable artifacts next to it:

  * findings.json   - a single pretty-printed array (easy to diff between runs,
                      import into other tooling, or feed to a SIEM)
  * findings.csv    - spreadsheet-friendly
  * findings.sarif  - SARIF 2.1.0, so the results drop straight into GitHub code
                      scanning / DefectDojo / any SARIF viewer

Each finding is enriched with a stable id and a best-effort MITRE ATT&CK
technique mapping derived from its category (no need to annotate every
add_finding call site).

Usage: report_export.py <findings.jsonl> <output_dir>
"""

import csv
import hashlib
import json
import os
import sys

# Category (case-insensitive substring) -> MITRE ATT&CK technique id(s).
ATTACK_MAP = [
    ("kerberoast",            ["T1558.003"]),
    ("as-rep",               ["T1558.004"]),
    ("asrep",                ["T1558.004"]),
    ("dcsync",               ["T1003.006"]),
    ("gpp password",          ["T1552.006"]),
    ("credential",            ["T1552"]),
    ("password in",           ["T1552.001"]),
    ("script credential",     ["T1552.001"]),
    ("ini credential",        ["T1552.001"]),
    ("connection string",     ["T1552.001"]),
    ("api key",               ["T1552.001"]),
    ("laps",                 ["T1555"]),
    ("gmsa",                 ["T1555"]),
    ("unconstrained delegation", ["T1558", "T1187"]),
    ("constrained delegation",   ["T1558.003"]),
    ("rbcd",                 ["T1558.003"]),
    ("protocol transition",   ["T1558.003"]),
    ("adcs",                 ["T1649"]),
    ("certificate",           ["T1649"]),
    ("shadow credential",     ["T1556.005"]),
    ("attack path",           ["T1078", "T1098"]),
    ("acl",                  ["T1222.001"]),
    ("gpo",                  ["T1484.001"]),
    ("trust",                ["T1482"]),
    ("sid history",           ["T1134.005"]),
    ("sid filtering",         ["T1134.005"]),
    ("share",                ["T1135"]),
    ("session",              ["T1049"]),
    ("scheduled task",        ["T1053.005"]),
    ("service",              ["T1543.003"]),
    ("wmi",                  ["T1546.003"]),
    ("autorun",              ["T1547.001"]),
    ("dll hijack",            ["T1574.001"]),
    ("com hijack",            ["T1546.015"]),
    ("logon script",          ["T1037.001"]),
    ("startup script",        ["T1037"]),
    ("reversible",            ["T1552"]),
    ("password policy",       ["T1201"]),
    ("kerberos encryption",   ["T1558"]),
    ("machine account quota", ["T1136.002"]),
    ("dormant",              ["T1078.002"]),
    ("end-of-life",           ["T1190"]),
    ("infrastructure",        ["T1018"]),
    ("bloodhound",            ["T1087.002"]),
    ("foreign security",      ["T1482"]),
]

SARIF_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "INFO": "note"}
SECURITY_SEVERITY = {"CRITICAL": "9.5", "HIGH": "8.0", "MEDIUM": "5.0", "INFO": "1.0"}


def attack_for(category):
    cat = (category or "").lower()
    for needle, techniques in ATTACK_MAP:
        if needle in cat:
            return techniques
    return []


def finding_id(f, idx):
    h = hashlib.sha1(
        f"{f.get('level','')}|{f.get('category','')}|{f.get('message','')}".encode("utf-8")
    ).hexdigest()[:10]
    return f"ADENUM-{idx:04d}-{h}"


def load(jsonl_path):
    findings = []
    if not os.path.exists(jsonl_path):
        return findings
    with open(jsonl_path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            findings.append(obj)
    for i, f in enumerate(findings, 1):
        f["id"] = finding_id(f, i)
        f["attack"] = attack_for(f.get("category", ""))
    return findings


def write_json(findings, out_dir):
    with open(os.path.join(out_dir, "findings.json"), "w", encoding="utf-8") as fh:
        json.dump(findings, fh, indent=2)


def write_csv(findings, out_dir):
    cols = ["id", "level", "category", "message", "exploit_ref", "attack", "timestamp"]
    with open(os.path.join(out_dir, "findings.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(cols)
        for f in findings:
            w.writerow([
                f.get("id", ""), f.get("level", ""), f.get("category", ""),
                f.get("message", ""), f.get("exploit_ref", ""),
                ",".join(f.get("attack", [])), f.get("timestamp", ""),
            ])


def write_sarif(findings, out_dir):
    rules = {}
    results = []
    for f in findings:
        cat = f.get("category", "Finding")
        rule_id = "adenum/" + cat.lower().replace(" ", "_").replace("/", "_")
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": cat.replace(" ", ""),
                "shortDescription": {"text": cat},
                "properties": {
                    "tags": ["security", "active-directory"] + f.get("attack", []),
                },
            }
        results.append({
            "ruleId": rule_id,
            "level": SARIF_LEVEL.get(f.get("level", "INFO"), "note"),
            "message": {"text": f.get("message", "")},
            # AD findings are not tied to a source file/line, but GitHub code
            # scanning (and some strict SARIF consumers) require a physical
            # location to ingest a result. Point each at a synthetic per-category
            # artifact so the SARIF imports cleanly instead of being rejected.
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": "active-directory/" + cat.lower().replace(" ", "_").replace("/", "_")},
                    "region": {"startLine": 1},
                },
            }],
            "properties": {
                "id": f.get("id", ""),
                "severity": f.get("level", ""),
                "exploitation": f.get("exploit_ref", ""),
                "attack": f.get("attack", []),
                "security-severity": SECURITY_SEVERITY.get(f.get("level", "INFO"), "1.0"),
            },
        })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "adenum",
                "informationUri": "https://github.com/",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }
    with open(os.path.join(out_dir, "findings.sarif"), "w", encoding="utf-8") as fh:
        json.dump(sarif, fh, indent=2)


def main():
    if len(sys.argv) < 3:
        print("Usage: report_export.py <findings.jsonl> <output_dir>", file=sys.stderr)
        sys.exit(1)
    jsonl_path, out_dir = sys.argv[1], sys.argv[2]
    findings = load(jsonl_path)
    os.makedirs(out_dir, exist_ok=True)
    write_json(findings, out_dir)
    write_csv(findings, out_dir)
    write_sarif(findings, out_dir)
    print(f"[+] Exported {len(findings)} findings -> findings.json / .csv / .sarif", file=sys.stderr)


if __name__ == "__main__":
    main()
