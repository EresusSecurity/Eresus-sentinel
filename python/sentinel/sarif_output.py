"""SARIF v2.1.0 output — full compliance with code flows, related locations, GitHub integration."""
from __future__ import annotations

import hashlib
import json
import subprocess
import time

from sentinel import __version__
from sentinel.finding import Finding, Severity

_SEVERITY_MAP = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

_SEVERITY_RANK = {
    Severity.CRITICAL: "critical",
    Severity.HIGH: "high",
    Severity.MEDIUM: "medium",
    Severity.LOW: "low",
    Severity.INFO: "informational",
}

CWE_HELP_BASE = "https://cwe.mitre.org/data/definitions/"

RULE_HELP = {
    "PICKLE": "https://eresussec.com/docs/rules/pickle",
    "TORCH": "https://eresussec.com/docs/rules/torch",
    "ONNX": "https://eresussec.com/docs/rules/onnx",
    "SAFETENSORS": "https://eresussec.com/docs/rules/safetensors",
    "GGUF": "https://eresussec.com/docs/rules/gguf",
    "NET": "https://eresussec.com/docs/rules/network",
    "SYM": "https://eresussec.com/docs/rules/symbols",
    "JIT": "https://eresussec.com/docs/rules/jit",
    "CVE": "https://eresussec.com/docs/rules/cve",
    "OCI": "https://eresussec.com/docs/rules/oci",
    "7Z": "https://eresussec.com/docs/rules/7z",
    "MANIFEST": "https://eresussec.com/docs/rules/manifest",
    "JINJA2": "https://eresussec.com/docs/rules/jinja2",
    "COMPRESSED": "https://eresussec.com/docs/rules/compressed",
    "RAR": "https://eresussec.com/docs/rules/rar",
    "MODEL-SECRET": "https://eresussec.com/docs/rules/secrets",
    "SCAN-SIZE": "https://eresussec.com/docs/rules/size-limits",
}


def _get_rule_help_uri(rule_id: str) -> str:
    prefix = rule_id.split("-")[0] if "-" in rule_id else rule_id
    return RULE_HELP.get(prefix, f"https://eresussec.com/docs/rules/{prefix.lower()}")


def _build_rule(finding: Finding) -> dict:
    rule_id = finding.rule_id or "UNKNOWN"
    rule: dict = {
        "id": rule_id,
        "name": rule_id.replace("-", ""),
        "shortDescription": {"text": finding.title or rule_id},
        "fullDescription": {"text": finding.description or ""},
        "defaultConfiguration": {
            "level": _SEVERITY_MAP.get(finding.severity, "warning"),
        },
        "helpUri": _get_rule_help_uri(rule_id),
        "help": {
            "text": finding.description or "",
            "markdown": f"**{finding.title or rule_id}**\n\n{finding.description or ''}",
        },
        "properties": {
            "tags": list(finding.tags) if finding.tags else [],
            "security-severity": _security_severity_score(finding.severity),
            "precision": "high" if finding.confidence and finding.confidence > 0.8 else "medium",
        },
    }
    if finding.cwe_ids:
        rule["properties"]["cwe"] = finding.cwe_ids
        rule["relationships"] = [
            {
                "target": {"id": cwe, "guid": hashlib.sha256(cwe.encode()).hexdigest()[:8] + "-0000-0000-0000-000000000000",
                           "toolComponent": {"name": "CWE", "guid": "a0a0a0a0-0000-0000-0000-000000000cwe"}},
                "kinds": ["superset"],
            }
            for cwe in finding.cwe_ids
        ]
    if finding.remediation:
        rule["help"]["markdown"] += f"\n\n**Remediation:** {finding.remediation}"
    return rule


def _security_severity_score(severity: Severity) -> str:
    scores = {Severity.CRITICAL: "9.8", Severity.HIGH: "8.0", Severity.MEDIUM: "5.5", Severity.LOW: "3.0", Severity.INFO: "1.0"}
    return scores.get(severity, "5.0")


def _build_result(finding: Finding, rule_index: int) -> dict:
    result: dict = {
        "ruleId": finding.rule_id or "UNKNOWN",
        "ruleIndex": rule_index,
        "level": _SEVERITY_MAP.get(finding.severity, "warning"),
        "message": {"text": finding.description or finding.title or ""},
        "kind": "fail",
    }

    locations = _build_locations(finding)
    if locations:
        result["locations"] = locations

    related = _build_related_locations(finding)
    if related:
        result["relatedLocations"] = related

    code_flows = _build_code_flows(finding)
    if code_flows:
        result["codeFlows"] = code_flows

    fingerprints = _build_fingerprints(finding)
    if fingerprints:
        result["fingerprints"] = fingerprints
        result["partialFingerprints"] = {
            "primaryLocationLineHash": hashlib.sha256(
                f"{finding.rule_id}:{finding.target or ''}".encode()
            ).hexdigest()[:16],
        }

    fixes = _build_fixes(finding)
    if fixes:
        result["fixes"] = fixes

    props: dict = {}
    if finding.confidence is not None:
        props["confidence"] = finding.confidence
    if finding.tags:
        props["tags"] = list(finding.tags)
    if finding.remediation:
        props["remediation"] = finding.remediation
    sev_rank = _SEVERITY_RANK.get(finding.severity)
    if sev_rank:
        props["security-severity"] = sev_rank
    if props:
        result["properties"] = props

    return result


def _build_locations(finding: Finding) -> list[dict]:
    locations = []
    if finding.location:
        physical: dict = {}
        if finding.location.file:
            physical["artifactLocation"] = {"uri": finding.location.file, "uriBaseId": "%SRCROOT%"}
        region: dict = {}
        if finding.location.line:
            region["startLine"] = finding.location.line
        if finding.location.end_line:
            region["endLine"] = finding.location.end_line
        if finding.location.byte_offset is not None:
            region["byteOffset"] = finding.location.byte_offset
            region["byteLength"] = finding.location.byte_length or 0
        if region:
            physical["region"] = region
        if physical:
            loc: dict = {"physicalLocation": physical}
            locations.append(loc)
    elif finding.target:
        locations.append({
            "physicalLocation": {
                "artifactLocation": {"uri": finding.target, "uriBaseId": "%SRCROOT%"},
            },
        })
    return locations


def _build_related_locations(finding: Finding) -> list[dict]:
    related = []
    if finding.evidence:
        related.append({
            "id": 0,
            "message": {"text": f"Evidence: {finding.evidence[:256]}"},
            "physicalLocation": {
                "artifactLocation": {"uri": finding.target or "unknown", "uriBaseId": "%SRCROOT%"},
            },
        })
    return related


def _build_code_flows(finding: Finding) -> list[dict]:
    if not finding.location or not finding.location.byte_offset:
        return []
    return [{
        "threadFlows": [{
            "locations": [{
                "location": {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.location.file or finding.target or "", "uriBaseId": "%SRCROOT%"},
                        "region": {"byteOffset": finding.location.byte_offset},
                    },
                    "message": {"text": finding.title or ""},
                },
                "importance": "essential",
            }],
        }],
    }]


def _build_fingerprints(finding: Finding) -> dict:
    fp: dict = {}
    if finding.evidence:
        fp["evidence/v1"] = finding.evidence[:256]
    content = f"{finding.rule_id}:{finding.target}:{finding.title}"
    fp["sentinel/v1"] = hashlib.sha256(content.encode()).hexdigest()[:32]
    return fp


def _build_fixes(finding: Finding) -> list[dict]:
    if not finding.remediation:
        return []
    return [{
        "description": {"text": finding.remediation},
    }]


def findings_to_sarif(
    findings: list[Finding],
    tool_name: str = "eresus-sentinel",
    tool_version: str = __version__,
    tool_uri: str = "https://github.com/eresus-security/sentinel",
    include_invocation: bool = True,
) -> dict:
    rules_map: dict[str, tuple[dict, int]] = {}
    results = []
    rule_index = 0

    for finding in findings:
        rid = finding.rule_id or "UNKNOWN"
        if rid not in rules_map:
            rules_map[rid] = (_build_rule(finding), rule_index)
            rule_index += 1
        _, idx = rules_map[rid]
        results.append(_build_result(finding, idx))

    run: dict = {
        "tool": {
            "driver": {
                "name": tool_name,
                "version": tool_version,
                "semanticVersion": tool_version,
                "informationUri": tool_uri,
                "rules": [r for r, _ in rules_map.values()],
                "properties": {"tags": ["security", "ml-security", "model-scanning"]},
            },
        },
        "results": results,
        "columnKind": "utf16CodeUnits",
    }

    if include_invocation:
        run["invocations"] = [{
            "executionSuccessful": True,
            "commandLine": "eresus-sentinel scan",
            "startTimeUtc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }]

    artifacts = set()
    for f in findings:
        target = f.target or (f.location.file if f.location else None)
        if target:
            artifacts.add(target)
    if artifacts:
        run["artifacts"] = [{"location": {"uri": a, "uriBaseId": "%SRCROOT%"}} for a in sorted(artifacts)]

    automations = _build_automation_details()
    if automations:
        run["automationDetails"] = automations

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
    }


def _build_automation_details() -> dict:
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"], capture_output=True, text=True, timeout=5,
        ).stdout.strip()
        if commit:
            return {"id": f"eresus-sentinel/{commit[:8]}", "guid": commit[:8] + "-0000-0000-0000-000000000000"}
    except Exception:
        pass
    return {}


def write_sarif(findings: list[Finding], output_path: str, **kwargs) -> None:
    sarif = findings_to_sarif(findings, **kwargs)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2, default=str)


def sarif_summary(sarif: dict) -> dict:
    results = sarif.get("runs", [{}])[0].get("results", [])
    by_level = {"error": 0, "warning": 0, "note": 0}
    for r in results:
        level = r.get("level", "warning")
        by_level[level] = by_level.get(level, 0) + 1
    rules = sarif.get("runs", [{}])[0].get("tool", {}).get("driver", {}).get("rules", [])
    return {
        "total_results": len(results),
        "by_level": by_level,
        "total_rules": len(rules),
        "has_code_flows": any("codeFlows" in r for r in results),
    }


def upload_to_github(sarif_path: str, repo: str, ref: str, commit_sha: str) -> dict:
    """Upload SARIF to GitHub Code Scanning via gh CLI."""
    import shutil
    if not shutil.which("gh"):
        return {"error": "gh CLI not found"}
    try:
        result = subprocess.run(
            ["gh", "api", "-X", "POST",
             f"/repos/{repo}/code-scanning/sarifs",
             "-f", f"commit_sha={commit_sha}",
             "-f", f"ref={ref}",
             "-f", f"sarif=@{sarif_path}",
             "-f", "tool_name=eresus-sentinel"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            return json.loads(result.stdout) if result.stdout else {"status": "uploaded"}
        return {"error": result.stderr}
    except Exception as e:
        return {"error": str(e)}


def merge_sarif_files(paths: list[str]) -> dict:
    """Merge multiple SARIF files into one."""
    merged_runs = []
    for p in paths:
        try:
            with open(p, "r") as f:
                data = json.load(f)
            merged_runs.extend(data.get("runs", []))
        except Exception:
            continue
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": merged_runs,
    }
