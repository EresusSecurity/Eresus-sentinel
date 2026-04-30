"""Scanner rule expansion — detection rules for known bypass patterns."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class RuleSeverity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class ScannerFinding:
    rule_id: str
    severity: RuleSeverity
    description: str
    offset: int = 0
    matched_bytes: bytes = b""


class PickleScannerRules:
    """Extended pickle scanner rules targeting known bypass vectors."""

    # Opcodes
    REDUCE = 0x52
    GLOBAL = 0x63
    STACK_GLOBAL = 0x8E
    INST = 0x69
    OBJ = 0x6F
    BUILD = 0x62
    NEWOBJ = 0x81
    NEWOBJ_EX = 0x92
    EXT1 = 0x82
    EXT2 = 0x83
    EXT4 = 0x84
    PROTO = 0x80
    STOP = 0x2E
    FRAME = 0x95
    MARK = 0x28
    EMPTY_DICT = 0x7D
    EMPTY_LIST = 0x5D
    SHORT_BINUNICODE = 0x8C
    BINUNICODE = 0x58

    # STACK_GLOBAL → REDUCE chain
    def check_stack_global_reduce(self, data: bytes) -> list[ScannerFinding]:
        findings = []
        i = 0
        while i < len(data) - 1:
            if data[i] == self.STACK_GLOBAL:
                j = i + 1
                while j < min(i + 50, len(data)):
                    if data[j] == self.REDUCE:
                        findings.append(ScannerFinding(
                            rule_id="PICKLE-STACK-GLOBAL-001",
                            severity=RuleSeverity.CRITICAL,
                            description="STACK_GLOBAL followed by REDUCE — arbitrary callable invocation",
                            offset=i,
                            matched_bytes=data[i:j + 1],
                        ))
                        break
                    j += 1
            i += 1
        return findings

    # copyreg/EXT opcode chain
    def check_copyreg_ext(self, data: bytes) -> list[ScannerFinding]:
        findings = []
        ext_opcodes = {self.EXT1, self.EXT2, self.EXT4}
        for i, b in enumerate(data):
            if b in ext_opcodes:
                findings.append(ScannerFinding(
                    rule_id="PICKLE-EXT-001",
                    severity=RuleSeverity.HIGH,
                    description=f"EXT opcode (0x{b:02x}) — copyreg dispatch table abuse",
                    offset=i,
                    matched_bytes=data[i:i + 5],
                ))
        return findings

    # Nested deserialization (pickle inside pickle)
    def check_nested_deser(self, data: bytes) -> list[ScannerFinding]:
        findings = []
        pickle_magic = [b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05"]
        for i in range(1, len(data) - 2):
            for magic in pickle_magic:
                if data[i:i + len(magic)] == magic:
                    # Check if there's a STOP before this — nested pickle
                    if self.STOP in data[:i]:
                        findings.append(ScannerFinding(
                            rule_id="PICKLE-NESTED-001",
                            severity=RuleSeverity.CRITICAL,
                            description="Nested pickle stream detected — potential deserialization chain",
                            offset=i,
                            matched_bytes=data[i:i + 4],
                        ))
        return findings

    # Protocol mismatch
    def check_protocol_mismatch(self, data: bytes) -> list[ScannerFinding]:
        findings = []
        if len(data) < 2:
            return findings
        if data[0] == self.PROTO:
            declared = data[1]
            # Check for opcodes from different protocols
            high_proto_opcodes = {0x8C, 0x8D, 0x8E, 0x92, 0x93, 0x94, 0x95, 0x96}
            low_proto_opcodes = {0x63, 0x69}  # GLOBAL, INST (proto 0)
            has_high = any(b in high_proto_opcodes for b in data[2:])
            has_low = any(b in low_proto_opcodes for b in data[2:])

            if declared >= 4 and has_low:
                findings.append(ScannerFinding(
                    rule_id="PICKLE-PROTO-001",
                    severity=RuleSeverity.MEDIUM,
                    description=f"Protocol {declared} declared but uses proto-0 opcodes — evasion attempt",
                    offset=0,
                ))
            if declared <= 1 and has_high:
                findings.append(ScannerFinding(
                    rule_id="PICKLE-PROTO-002",
                    severity=RuleSeverity.MEDIUM,
                    description=f"Protocol {declared} declared but uses high-proto opcodes — evasion attempt",
                    offset=0,
                ))
        return findings

    # Multi-stage REDUCE chains
    def check_multi_stage_chain(self, data: bytes) -> list[ScannerFinding]:
        findings = []
        reduce_positions = [i for i, b in enumerate(data) if b == self.REDUCE]
        if len(reduce_positions) >= 3:
            # More than 2 REDUCE ops is suspicious
            findings.append(ScannerFinding(
                rule_id="PICKLE-CHAIN-001",
                severity=RuleSeverity.HIGH,
                description=f"Multi-stage REDUCE chain detected ({len(reduce_positions)} REDUCE ops)",
                offset=reduce_positions[0],
            ))
        # Check for REDUCE → BUILD → REDUCE (chain via __setstate__)
        for i in range(len(data) - 3):
            if data[i] == self.REDUCE and data[i + 1] == self.BUILD:
                for j in range(i + 2, min(i + 30, len(data))):
                    if data[j] == self.REDUCE:
                        findings.append(ScannerFinding(
                            rule_id="PICKLE-CHAIN-002",
                            severity=RuleSeverity.CRITICAL,
                            description="REDUCE → BUILD → REDUCE chain — __setstate__ abuse",
                            offset=i,
                        ))
                        break
        return findings

    # Deep nesting (resource exhaustion)
    def check_deep_nesting(self, data: bytes, max_depth: int = 100) -> list[ScannerFinding]:
        findings = []
        nesting = 0
        max_seen = 0
        openers = {self.MARK, self.EMPTY_DICT, self.EMPTY_LIST}
        for b in data:
            if b in openers:
                nesting += 1
                max_seen = max(max_seen, nesting)
            elif b == self.REDUCE or b == self.STOP:
                nesting = max(0, nesting - 1)

        if max_seen > max_depth:
            findings.append(ScannerFinding(
                rule_id="PICKLE-NEST-001",
                severity=RuleSeverity.MEDIUM,
                description=f"Excessive nesting depth ({max_seen}) — potential resource exhaustion",
                offset=0,
            ))
        return findings

    # Circular memo reference
    def check_circular_memo(self, data: bytes) -> list[ScannerFinding]:
        findings = []
        # PUT/BINPUT/LONG_BINPUT
        put_ops = {0x70, 0x71, 0x72}  # PUT, BINPUT, LONG_BINPUT
        get_ops = {0x67, 0x68, 0x6A}  # GET, BINGET, LONG_BINGET
        memo_puts: list[int] = []
        memo_gets_before_put: list[int] = []

        for i, b in enumerate(data):
            if b in put_ops:
                memo_puts.append(i)
            elif b in get_ops:
                if not memo_puts:
                    memo_gets_before_put.append(i)

        if memo_gets_before_put:
            findings.append(ScannerFinding(
                rule_id="PICKLE-MEMO-001",
                severity=RuleSeverity.HIGH,
                description=f"GET before PUT — circular memo reference ({len(memo_gets_before_put)} instances)",
                offset=memo_gets_before_put[0],
            ))
        return findings

    # Dangerous globals
    DANGEROUS_MODULES = {
        "os", "subprocess", "sys", "builtins", "posixpath",
        "nt", "posix", "shutil", "importlib", "ctypes",
        "pickle", "marshal", "code", "codeop", "compile",
        "exec", "eval", "webbrowser", "socket", "http",
    }

    DANGEROUS_ATTRS = {
        "system", "popen", "exec", "eval", "execfile",
        "compile", "import", "__import__", "call", "Popen",
        "check_output", "run", "load", "loads", "getattr",
        "setattr", "delattr", "__subclasses__", "register",
    }

    def check_dangerous_globals(self, data: bytes) -> list[ScannerFinding]:
        findings = []
        # GLOBAL opcode: c<module>\n<name>\n
        i = 0
        while i < len(data):
            if data[i] == self.GLOBAL:
                j = i + 1
                newline1 = data.find(b"\n", j)
                if newline1 == -1:
                    break
                newline2 = data.find(b"\n", newline1 + 1)
                if newline2 == -1:
                    break
                try:
                    module = data[j:newline1].decode("ascii", errors="ignore")
                    attr = data[newline1 + 1:newline2].decode("ascii", errors="ignore")
                except Exception:
                    i = newline2 + 1
                    continue

                if module in self.DANGEROUS_MODULES or attr in self.DANGEROUS_ATTRS:
                    findings.append(ScannerFinding(
                        rule_id="PICKLE-GLOBAL-001",
                        severity=RuleSeverity.CRITICAL,
                        description=f"Dangerous global: {module}.{attr}",
                        offset=i,
                        matched_bytes=data[i:newline2 + 1],
                    ))
                i = newline2 + 1
            else:
                i += 1
        return findings

    def scan(self, data: bytes) -> list[ScannerFinding]:
        """Run all scanner rules."""
        findings = []
        findings.extend(self.check_stack_global_reduce(data))
        findings.extend(self.check_copyreg_ext(data))
        findings.extend(self.check_nested_deser(data))
        findings.extend(self.check_protocol_mismatch(data))
        findings.extend(self.check_multi_stage_chain(data))
        findings.extend(self.check_deep_nesting(data))
        findings.extend(self.check_circular_memo(data))
        findings.extend(self.check_dangerous_globals(data))
        return findings
