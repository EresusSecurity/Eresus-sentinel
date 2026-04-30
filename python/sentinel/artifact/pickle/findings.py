"""Finding builders for each pickle detection class."""

from __future__ import annotations

from ...finding import Finding, Location, Severity
from .._pickle_ops import (
    GET_PUT_RATIO_CRIT,
    PickleAnalysis,
)
from .._pickle_rules import rule_id_for_module


def _fallback_has_evasion_signal(analysis: PickleAnalysis) -> bool:
    """Only escalate parser fallback when raw scan found pickle-risk signals."""
    return any(
        (
            analysis.dangerous_imports,
            analysis.suspicious_global_mutations,
            analysis.has_reduce,
            analysis.has_nested_pickle,
            analysis.has_nested_yaml,
            analysis.has_tar_format,
            analysis.has_codetype_construction,
            analysis.has_ext_registry_abuse,
        )
    )


def build_findings(analysis: PickleAnalysis, source: str) -> list[Finding]:
    """Convert a PickleAnalysis into a list of Finding objects."""
    findings: list[Finding] = []

    # ── Dangerous import findings ────────────────────────────
    for imp in analysis.dangerous_imports:
        payload_info = ""
        if imp.payload_args:
            payload_info = f" Extracted payload args: {imp.payload_args[:3]}"

        chain_info = ""
        if imp.chain_confirmed:
            chain_info = (
                " \u26a0 REDUCE opcode confirms this import WILL EXECUTE "
                "during deserialization \u2014 confirmed RCE vector."
            )

        findings.append(Finding.artifact(
            rule_id=rule_id_for_module(imp.module, imp.opcode),
            title=f"Dangerous pickle import: {imp.module}.{imp.name}",
            description=(
                f"The pickle stream at '{source}' contains a {imp.opcode} opcode "
                f"that imports '{imp.module}.{imp.name}'. This import can execute "
                f"arbitrary code during deserialization."
                f"{chain_info}{payload_info}"
            ),
            severity=imp.severity,
            confidence=imp.confidence,
            target=source,
            evidence=(
                f"Opcode: {imp.opcode} at position {imp.position}, "
                f"import: {imp.module}.{imp.name}, "
                f"confidence: {imp.confidence:.1f}, "
                f"chain_confirmed: {imp.chain_confirmed}"
            ),
            location=Location(file=source, byte_offset=imp.position),
            cwe_ids=["CWE-502"],
            tags=[
                "avid-effect:security:S0403",
                "owasp:llm05",
                "mitre-atlas:AML.T0010",
            ],
        ))

    # ── Mutated dangerous GLOBAL findings ──────────────────────
    for imp in analysis.suspicious_global_mutations:
        near_miss = next(
            (arg.split("=", 1)[1] for arg in imp.payload_args if arg.startswith("near_miss=")),
            "a blocklisted global",
        )
        findings.append(Finding.artifact(
            rule_id="ARTIFACT-041",
            title=f"Suspicious mutated pickle global: {imp.module}.{imp.name}",
            description=(
                f"The pickle stream at '{source}' contains a GLOBAL opcode that is "
                f"one mutation away from {near_miss} and is followed by an execution "
                "opcode. This is characteristic of fuzzed or tampered pickle payloads "
                "attempting to evade exact blocklist matching."
            ),
            severity=imp.severity,
            confidence=imp.confidence,
            target=source,
            evidence=(
                f"Opcode: {imp.opcode} at position {imp.position}, "
                f"mutated import: {imp.module}.{imp.name}, "
                f"chain_confirmed: {imp.chain_confirmed}"
            ),
            location=Location(file=source, byte_offset=imp.position),
            cwe_ids=["CWE-502"],
            tags=[
                "avid-effect:security:S0403",
                "owasp:llm05",
                "evasion:mutated-global",
            ],
        ))

    # ── Protocol version ─────────────────────────────────────
    if analysis.protocol_version in (0, 1):
        findings.append(Finding.artifact(
            rule_id="ARTIFACT-015",
            title=f"Legacy pickle protocol v{analysis.protocol_version}",
            description=(
                f"The file uses pickle protocol {analysis.protocol_version}, "
                "which has reduced security boundaries."
            ),
            severity=Severity.MEDIUM,
            confidence=0.6,
            target=source,
            evidence=f"Protocol version: {analysis.protocol_version}",
            cwe_ids=["CWE-502"],
        ))

    # ── Nested pickle ────────────────────────────────────────
    if analysis.has_nested_pickle:
        findings.append(Finding.artifact(
            rule_id="ARTIFACT-016",
            title="Nested pickle detected (double deserialization)",
            description=(
                "The pickle stream contains embedded pickle protocol headers, "
                "indicating a pickle-within-pickle used to chain exploits."
            ),
            severity=Severity.HIGH,
            confidence=0.8,
            target=source,
            evidence="Multiple pickle protocol headers detected",
            cwe_ids=["CWE-502"],
        ))

    # ── Nested YAML ──────────────────────────────────────────
    if analysis.has_nested_yaml:
        findings.append(Finding.artifact(
            rule_id="ARTIFACT-018",
            title="Nested YAML deserialization detected",
            description=(
                "String payloads contain !!python/object/apply markers, "
                "indicating YAML-based code execution nested inside pickle."
            ),
            severity=Severity.CRITICAL,
            confidence=0.9,
            target=source,
            evidence="YAML !!python/object/apply in pickle string args",
            cwe_ids=["CWE-502"],
        ))

    # ── Obfuscation ──────────────────────────────────────────
    if analysis.obfuscation_detected:
        findings.append(Finding.artifact(
            rule_id="ARTIFACT-017",
            title="Pickle payload obfuscation detected",
            description=(
                "Encoding modules (base64, codecs, marshal, zlib) "
                "are imported in the pickle stream, suggesting payload "
                "obfuscation to evade pattern-based scanners."
            ),
            severity=Severity.HIGH,
            confidence=0.9,
            target=source,
            evidence="Obfuscation module imports detected in pickle opcodes",
            cwe_ids=["CWE-502"],
        ))

    # ── Introspection chain ──────────────────────────────────
    if analysis.has_introspection_chain:
        findings.append(Finding.artifact(
            rule_id="ARTIFACT-019",
            title="Python introspection chain detected",
            description=(
                "The pickle uses __subclasses__/__builtins__ chaining "
                "to reach eval/exec from builtins-only GLOBAL opcodes. "
                "This technique bypasses module-level blocklists."
            ),
            severity=Severity.CRITICAL,
            confidence=0.95,
            target=source,
            evidence="Introspection via __subclasses__ \u2192 __builtins__",
            cwe_ids=["CWE-502"],
        ))

    # ── EXT registry abuse ───────────────────────────────────
    if analysis.has_ext_registry_abuse:
        findings.append(Finding.artifact(
            rule_id="ARTIFACT-092",
            title="copyreg extension registry abuse detected",
            description=(
                "The pickle registers dangerous functions via "
                "copyreg.add_extension and invokes them via EXT opcodes, "
                "bypassing GLOBAL/STACK_GLOBAL scanning."
            ),
            severity=Severity.CRITICAL,
            confidence=0.95,
            target=source,
            evidence=f"Registered extensions: {analysis.copyreg_extensions}",
            cwe_ids=["CWE-502"],
        ))

    # ── CodeType construction ────────────────────────────────
    if analysis.has_codetype_construction:
        findings.append(Finding.artifact(
            rule_id="ARTIFACT-020",
            title="CodeType/FunctionType construction detected",
            description=(
                "The pickle constructs executable code objects via "
                "types.CodeType + types.FunctionType, embedding raw "
                "Python bytecode that evades pattern-based detection."
            ),
            severity=Severity.CRITICAL,
            confidence=0.95,
            target=source,
            evidence="CodeType/FunctionType/marshal.loads in pickle stream",
            cwe_ids=["CWE-502"],
        ))

    # ── Byte-scan fallback ───────────────────────────────────
    if analysis.byte_scan_fallback and _fallback_has_evasion_signal(analysis):
        findings.append(Finding.artifact(
            rule_id="ARTIFACT-000",
            title="Pickle opcode parser crashed \u2014 evasion technique detected",
            description=(
                "pickletools.genops() raised an exception on this file. "
                "This is a known evasion technique (truncated opcodes after "
                "the malicious REDUCE payload). Findings from raw byte scan."
            ),
            severity=Severity.CRITICAL,
            confidence=0.9,
            target=source,
            evidence="pickletools crash \u2192 raw byte scan fallback",
            cwe_ids=["CWE-502"],
        ))

    # ── Duplicate PROTO ──────────────────────────────────────
    if analysis.has_duplicate_proto:
        findings.append(Finding.artifact(
            rule_id="ARTIFACT-030",
            title="Duplicate PROTO opcode detected (tampered pickle)",
            description=(
                "The pickle contains multiple PROTO opcodes. A valid pickle "
                "has exactly one PROTO at position 0."
            ),
            severity=Severity.HIGH,
            confidence=0.9,
            target=source,
            evidence="Multiple PROTO opcodes in single pickle stream",
            cwe_ids=["CWE-502"],
        ))

    # ── Misplaced PROTO ──────────────────────────────────────
    if analysis.has_misplaced_proto:
        findings.append(Finding.artifact(
            rule_id="ARTIFACT-031",
            title="Misplaced PROTO opcode (protocol violation)",
            description=(
                "For pickle protocol >= 2, the PROTO opcode must be "
                "the first opcode. A misplaced PROTO may indicate "
                "a tampered file attempting to bypass analysis."
            ),
            severity=Severity.HIGH,
            confidence=0.85,
            target=source,
            evidence="PROTO opcode not at position 0",
            cwe_ids=["CWE-502"],
        ))

    # ── Expansion attack ─────────────────────────────────────
    if analysis.has_expansion_attack:
        severity = (
            Severity.HIGH if analysis.get_put_ratio >= GET_PUT_RATIO_CRIT
            else Severity.MEDIUM
        )
        findings.append(Finding.artifact(
            rule_id="ARTIFACT-032",
            title="Expansion attack pattern detected (high GET/PUT ratio)",
            description=(
                f"GET/PUT ratio is {analysis.get_put_ratio:.1f}:1 \u2014 "
                "indicative of exponential expansion attack (Billion Laughs)."
            ),
            severity=severity,
            confidence=0.8,
            target=source,
            evidence=(
                f"GET/PUT ratio: {analysis.get_put_ratio:.1f}:1, "
                f"DUP count: {analysis.dup_count}"
            ),
            cwe_ids=["CWE-400", "CWE-502"],
        ))

    # ── Invalid opcode ───────────────────────────────────────
    if analysis.has_invalid_opcode:
        findings.append(Finding.artifact(
            rule_id="ARTIFACT-033",
            title="Invalid pickle opcodes detected",
            description=(
                "The pickle stream contains invalid opcodes or exceeds "
                "resource limits, indicating corruption or bypass attempt."
            ),
            severity=Severity.HIGH,
            confidence=0.85,
            target=source,
            evidence="Invalid opcode sequence in pickle stream",
            cwe_ids=["CWE-502"],
        ))

    # ── __setstate__ gadget ───────────────────────────────────
    if analysis.has_setstate_gadget:
        findings.append(Finding.artifact(
            rule_id="ARTIFACT-035",
            title="BUILD opcode __setstate__ gadget detected",
            description=(
                "The pickle uses BUILD opcode after NEWOBJ/REDUCE. "
                "BUILD calls __setstate__ which can merge dicts and "
                "inject dangerous attributes \u2014 confirmed gadget chain."
            ),
            severity=Severity.CRITICAL,
            confidence=0.9,
            target=source,
            evidence="GLOBAL+REDUCE\u2192BUILD chain detected",
            cwe_ids=["CWE-502"],
        ))

    # ── Malformed pickle fallback ────────────────────────────
    if analysis.byte_scan_fallback and analysis.parse_error:
        # Escalate to HIGH if exec opcodes present but no dangerous imports found
        has_exec_signal = analysis.has_reduce and not analysis.dangerous_imports
        findings.append(Finding.artifact(
            rule_id="ARTIFACT-040",
            title="Malformed pickle stream" + (" with execution opcodes" if has_exec_signal else ""),
            description=(
                "Pickle opcode parsing failed and Sentinel had to fall back to raw byte scanning. "
                "Malformed pickle streams can be used to evade opcode-based scanners."
                + (" Execution opcodes (REDUCE/NEWOBJ/BUILD) were found despite "
                   "string-level evasion — high risk of obfuscated RCE." if has_exec_signal else "")
            ),
            severity=Severity.HIGH if has_exec_signal else Severity.MEDIUM,
            confidence=0.8 if has_exec_signal else 0.7,
            target=source,
            evidence=analysis.parse_error[:200],
            cwe_ids=["CWE-502"],
        ))

    # ── OBJ+POP invisibility ─────────────────────────────────
    if analysis.has_obj_pop_bypass:
        findings.append(Finding.artifact(
            rule_id="ARTIFACT-036",
            title="OBJ+POP invisibility bypass detected",
            description=(
                "The pickle uses OBJ opcode to call a constructor, then "
                "immediately POP discards the result. Side effects still "
                "occur even though the result is invisible to the stack."
            ),
            severity=Severity.CRITICAL,
            confidence=0.95,
            target=source,
            evidence="OBJ followed by POP \u2014 side-effect-only pattern",
            cwe_ids=["CWE-502"],
        ))

    # ── Unused variables ─────────────────────────────────────
    if analysis.has_unused_assignments and any(
        imp.chain_confirmed for imp in analysis.dangerous_imports + analysis.suspicious_global_mutations
    ):
        findings.append(Finding.artifact(
            rule_id="ARTIFACT-034",
            title="Unused variable after REDUCE (side-effect-only operation)",
            description=(
                "REDUCE results stored in memo but never read. "
                "Characteristic of malicious side-effect-only code."
            ),
            severity=Severity.HIGH,
            confidence=0.85,
            target=source,
            evidence="REDUCE results stored in memo but never read via GET",
            cwe_ids=["CWE-502"],
        ))

    return findings
