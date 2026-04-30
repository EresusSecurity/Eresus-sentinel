"""Eresus Sentinel — MCP Transport Layer Fuzzer.

Low-level fuzzing of the MCP JSON-RPC 2.0 transport layer:
- Malformed JSON framing
- Oversized payloads / chunked overflow
- stdio transport abuse (delimiter injection, interleaved garbage)
- SSE transport abuse (malformed event streams, reconnect loops)
- Schema violation payloads (wrong types, missing required fields)
- Protocol state machine violations (out-of-order messages)
- Content-Length mismatch attacks
- Unicode / encoding torture tests
"""

from __future__ import annotations

import json
import logging
import random
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any

logger = logging.getLogger(__name__)


class TransportType(Enum):
    STDIO = auto()
    SSE = auto()
    WEBSOCKET = auto()
    HTTP = auto()


class FuzzCategory(Enum):
    MALFORMED_JSON = auto()
    OVERSIZED_PAYLOAD = auto()
    SCHEMA_VIOLATION = auto()
    STATE_MACHINE = auto()
    CONTENT_LENGTH = auto()
    ENCODING_TORTURE = auto()
    DELIMITER_INJECTION = auto()
    SSE_ABUSE = auto()
    HEADER_INJECTION = auto()
    CONCURRENT_ABUSE = auto()
    PROTOCOL_DOWNGRADE = auto()
    RESOURCE_EXHAUSTION = auto()


@dataclass
class TransportFuzzCase:
    case_id: str
    category: FuzzCategory
    transport: TransportType
    description: str
    payload: bytes
    expected_behavior: str = "reject"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class TransportFuzzResult:
    case_id: str
    category: FuzzCategory
    passed: bool
    response: bytes = b""
    error: str = ""
    latency_ms: float = 0.0
    description: str = ""


class MCPTransportFuzzer:
    """Low-level MCP transport protocol fuzzer.

    Generates adversarial payloads that target the transport layer
    rather than the application-level tool call semantics.
    """

    def __init__(self, seed: int | None = None):
        self._rng = random.Random(seed)
        self._cases: list[TransportFuzzCase] = []
        self._generate_all()

    @property
    def case_count(self) -> int:
        return len(self._cases)

    def get_cases(
        self,
        category: FuzzCategory | None = None,
        transport: TransportType | None = None,
    ) -> list[TransportFuzzCase]:
        cases = self._cases
        if category:
            cases = [c for c in cases if c.category == category]
        if transport:
            cases = [c for c in cases if c.transport == transport]
        return cases

    def get_stdio_payloads(self) -> list[bytes]:
        return [c.payload for c in self._cases if c.transport == TransportType.STDIO]

    def get_sse_payloads(self) -> list[bytes]:
        return [c.payload for c in self._cases if c.transport == TransportType.SSE]

    def get_http_payloads(self) -> list[bytes]:
        return [c.payload for c in self._cases if c.transport == TransportType.HTTP]

    # ── Generator orchestrator ───────────────────────────────────────

    def _generate_all(self) -> None:
        self._gen_malformed_json()
        self._gen_oversized_payloads()
        self._gen_schema_violations()
        self._gen_state_machine_violations()
        self._gen_content_length_mismatch()
        self._gen_encoding_torture()
        self._gen_delimiter_injection()
        self._gen_sse_abuse()
        self._gen_header_injection()
        self._gen_concurrent_abuse()
        self._gen_protocol_downgrade()
        self._gen_resource_exhaustion()

    # ── Malformed JSON ───────────────────────────────────────────────

    def _gen_malformed_json(self) -> None:
        payloads = [
            (b"", "Empty payload"),
            (b"\x00", "Null byte"),
            (b"\x00\x00\x00\x00", "Multiple null bytes"),
            (b"{", "Unclosed brace"),
            (b"}", "Dangling close brace"),
            (b"[", "Unclosed bracket"),
            (b"{{}}", "Double nested braces"),
            (b'{"jsonrpc":', "Truncated after key"),
            (b'{"jsonrpc": "2.0", "method":', "Truncated after method key"),
            (b'{"jsonrpc": "2.0", "method": "tools/list", "id":', "Truncated after id key"),
            (b'{"jsonrpc": "2.0",, "method": "test"}', "Double comma"),
            (b"{'jsonrpc': '2.0'}", "Single quotes"),
            (b'{jsonrpc: "2.0"}', "Unquoted key"),
            (b'{"jsonrpc": undefined}', "JS undefined value"),
            (b'{"jsonrpc": NaN}', "NaN value"),
            (b'{"jsonrpc": Infinity}', "Infinity value"),
            (b'{"jsonrpc": "2.0"}\x00{"method": "x"}', "Null-byte separated"),
            (b'\xef\xbb\xbf{"jsonrpc": "2.0"}', "BOM prefix"),
            (b'{"jsonrpc": "2.0"}\n\n\n', "Trailing newlines"),
            (b'\r\n\r\n{"jsonrpc": "2.0"}\r\n', "CRLF wrapped"),
            (b'{"jsonrpc": "2.0", "method": "test"} GARBAGE', "Trailing garbage"),
            (b'{"jsonrpc": "2.0", "__proto__": {"admin": true}}', "Prototype pollution attempt"),
            (b'{"jsonrpc": "2.0", "constructor": {"prototype": {"admin": true}}}', "Constructor pollution"),
        ]
        for i, (payload, desc) in enumerate(payloads):
            self._cases.append(TransportFuzzCase(
                case_id=f"malformed_json_{i:03d}",
                category=FuzzCategory.MALFORMED_JSON,
                transport=TransportType.STDIO,
                description=desc,
                payload=payload,
            ))

    # ── Oversized payloads ───────────────────────────────────────────

    def _gen_oversized_payloads(self) -> None:
        sizes = [
            (1024, "1KB"),
            (65536, "64KB"),
            (1048576, "1MB"),
            (10485760, "10MB"),
            (104857600, "100MB header only"),
        ]
        for size, label in sizes:
            if size <= 1048576:
                value = "A" * size
                payload = json.dumps({
                    "jsonrpc": "2.0", "method": "tools/call",
                    "params": {"name": "test", "arguments": {"data": value}},
                    "id": 1,
                }).encode()
            else:
                payload = b'{"jsonrpc":"2.0","method":"tools/call","params":{"data":"' + b"A" * min(size, 1048576) + b'"},"id":1}'

            self._cases.append(TransportFuzzCase(
                case_id=f"oversize_{label.replace(' ', '_')}",
                category=FuzzCategory.OVERSIZED_PAYLOAD,
                transport=TransportType.STDIO,
                description=f"Oversized payload: {label}",
                payload=payload,
                metadata={"target_size": size},
            ))

        deep = {"d": None}
        current = deep
        for _ in range(1000):
            current["d"] = {"d": None}  # type: ignore[index]
            current = current["d"]  # type: ignore[assignment]
        self._cases.append(TransportFuzzCase(
            case_id="oversize_deep_nesting",
            category=FuzzCategory.OVERSIZED_PAYLOAD,
            transport=TransportType.STDIO,
            description="Deeply nested JSON (1000 levels)",
            payload=json.dumps({"jsonrpc": "2.0", "method": "test", "params": deep, "id": 1}).encode(),
        ))

        wide = {f"key_{i}": f"value_{i}" for i in range(10000)}
        self._cases.append(TransportFuzzCase(
            case_id="oversize_wide_object",
            category=FuzzCategory.OVERSIZED_PAYLOAD,
            transport=TransportType.STDIO,
            description="Wide object (10K keys)",
            payload=json.dumps({"jsonrpc": "2.0", "method": "test", "params": wide, "id": 1}).encode(),
        ))

    # ── Schema violations ────────────────────────────────────────────

    def _gen_schema_violations(self) -> None:
        violations = [
            ({"method": "test", "id": 1}, "Missing jsonrpc field"),
            ({"jsonrpc": "1.0", "method": "test", "id": 1}, "Wrong jsonrpc version"),
            ({"jsonrpc": 2.0, "method": "test", "id": 1}, "jsonrpc as number"),
            ({"jsonrpc": "2.0", "id": 1}, "Missing method field"),
            ({"jsonrpc": "2.0", "method": 123, "id": 1}, "Method as number"),
            ({"jsonrpc": "2.0", "method": "", "id": 1}, "Empty method string"),
            ({"jsonrpc": "2.0", "method": None, "id": 1}, "Method is null"),
            ({"jsonrpc": "2.0", "method": True, "id": 1}, "Method is boolean"),
            ({"jsonrpc": "2.0", "method": "test", "id": None}, "ID is null"),
            ({"jsonrpc": "2.0", "method": "test", "id": [1, 2]}, "ID is array"),
            ({"jsonrpc": "2.0", "method": "test", "id": {"nested": 1}}, "ID is object"),
            ({"jsonrpc": "2.0", "method": "test", "id": 1, "params": "string"}, "Params as string"),
            ({"jsonrpc": "2.0", "method": "test", "id": 1, "params": 42}, "Params as number"),
            ({"jsonrpc": "2.0", "method": "test", "id": 1, "params": True}, "Params as boolean"),
            ({"jsonrpc": "2.0", "method": "test", "id": 1, "extra_field": "x"}, "Unknown extra field"),
            ({"jsonrpc": "2.0", "method": "tools/call", "id": 1, "params": {}}, "tools/call with empty params"),
            ({"jsonrpc": "2.0", "method": "tools/call", "id": 1, "params": {"name": ""}}, "tools/call with empty tool name"),
            ({"jsonrpc": "2.0", "method": "tools/call", "id": 1, "params": {"name": "test", "arguments": []}}, "Arguments as array"),
            ({"jsonrpc": "2.0", "method": "resources/read", "id": 1, "params": {}}, "resources/read with empty params"),
            ({"jsonrpc": "2.0", "method": "initialize", "id": 1, "params": {"protocolVersion": "999.0"}}, "Unknown protocol version"),
            ({"jsonrpc": "2.0", "method": "initialize", "id": 1, "params": {"capabilities": {"dangerous": True}}}, "Fake capability claim"),
            ({"jsonrpc": "2.0", "method": "sampling/createMessage", "id": 1}, "Sampling without params"),
        ]

        for i, (msg, desc) in enumerate(violations):
            self._cases.append(TransportFuzzCase(
                case_id=f"schema_violation_{i:03d}",
                category=FuzzCategory.SCHEMA_VIOLATION,
                transport=TransportType.STDIO,
                description=desc,
                payload=json.dumps(msg).encode(),
            ))

    # ── State machine violations ─────────────────────────────────────

    def _gen_state_machine_violations(self) -> None:
        sequences = [
            ([
                {"jsonrpc": "2.0", "method": "tools/list", "id": 1},
            ], "tools/list before initialize"),
            ([
                {"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "test"}, "id": 1},
            ], "tools/call before initialize"),
            ([
                {"jsonrpc": "2.0", "method": "initialize", "params": {"protocolVersion": "2024-11-05"}, "id": 1},
                {"jsonrpc": "2.0", "method": "initialize", "params": {"protocolVersion": "2024-11-05"}, "id": 2},
            ], "Double initialize"),
            ([
                {"jsonrpc": "2.0", "method": "initialized"},
            ], "initialized notification before initialize"),
            ([
                {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 999}},
            ], "Cancel non-existent request"),
            ([
                {"jsonrpc": "2.0", "method": "initialize", "params": {"protocolVersion": "2024-11-05"}, "id": 1},
                {"jsonrpc": "2.0", "method": "initialized"},
                {"jsonrpc": "2.0", "method": "initialized"},
            ], "Double initialized notification"),
        ]

        for i, (msgs, desc) in enumerate(sequences):
            combined = b"\n".join(json.dumps(m).encode() for m in msgs)
            self._cases.append(TransportFuzzCase(
                case_id=f"state_machine_{i:03d}",
                category=FuzzCategory.STATE_MACHINE,
                transport=TransportType.STDIO,
                description=desc,
                payload=combined,
                metadata={"message_count": len(msgs)},
            ))

    # ── Content-Length mismatch ───────────────────────────────────────

    def _gen_content_length_mismatch(self) -> None:
        body = b'{"jsonrpc":"2.0","method":"test","id":1}'
        patterns = [
            (f"Content-Length: {len(body) + 100}\r\n\r\n".encode() + body, "Content-Length too large"),
            (f"Content-Length: {len(body) - 10}\r\n\r\n".encode() + body, "Content-Length too small"),
            (b"Content-Length: 0\r\n\r\n" + body, "Content-Length zero with body"),
            (b"Content-Length: -1\r\n\r\n" + body, "Negative Content-Length"),
            (b"Content-Length: 999999999\r\n\r\n" + body, "Enormous Content-Length"),
            (b"Content-Length: abc\r\n\r\n" + body, "Non-numeric Content-Length"),
            (b"\r\n\r\n" + body, "Missing Content-Length header"),
            (f"Content-Length: {len(body)}\r\nContent-Length: 0\r\n\r\n".encode() + body, "Duplicate Content-Length"),
            (f"content-length: {len(body)}\r\n\r\n".encode() + body, "Lowercase header"),
            (f"CONTENT-LENGTH: {len(body)}\r\n\r\n".encode() + body, "Uppercase header"),
        ]

        for i, (payload, desc) in enumerate(patterns):
            self._cases.append(TransportFuzzCase(
                case_id=f"content_length_{i:03d}",
                category=FuzzCategory.CONTENT_LENGTH,
                transport=TransportType.HTTP,
                description=desc,
                payload=payload,
            ))

    # ── Encoding torture ─────────────────────────────────────────────

    def _gen_encoding_torture(self) -> None:
        payloads = [
            (b'\xff\xfe{"jsonrpc":"2.0"}', "UTF-16 LE BOM"),
            (b'\xfe\xff\x00{\x00"\x00j', "UTF-16 BE BOM fragment"),
            ('{"jsonrpc":"2.0","method":"✓✗★♠♥♦♣"}'.encode("utf-8"), "Unicode symbols in method"),
            ('{"jsonrpc":"2.0","method":"test","params":{"key":"\ud800"}}'.replace(
                "\ud800", "\\ud800"
            ).encode(), "Unpaired surrogate"),
            ('{"jsonrpc":"2.0","method":"te\x00st","id":1}'.encode(), "Null byte in method"),
            (b'{"jsonrpc":"2.0","method":"test\xc0\xaf","id":1}', "Overlong UTF-8 encoding"),
            (b'{"jsonrpc":"2.0","method":"\xe2\x80\x8b\xe2\x80\x8btest","id":1}', "ZWSP prefix in method"),
            (b'{"jsonrpc":"2.0","method":"\xe2\x80\xaetest","id":1}', "RTL override in method"),
            ('{"jsonrpc":"2.0","method":"ⓣⓔⓢⓣ","id":1}'.encode(), "Circled letters in method"),
            ('{"jsonrpc":"2.0","method":"tеst","id":1}'.encode(), "Cyrillic 'e' homoglyph"),
        ]

        for i, (payload, desc) in enumerate(payloads):
            self._cases.append(TransportFuzzCase(
                case_id=f"encoding_{i:03d}",
                category=FuzzCategory.ENCODING_TORTURE,
                transport=TransportType.STDIO,
                description=desc,
                payload=payload,
            ))

    # ── Delimiter injection ──────────────────────────────────────────

    def _gen_delimiter_injection(self) -> None:
        payloads = [
            (b'{"jsonrpc":"2.0","id":1}\n{"jsonrpc":"2.0","method":"tools/list","id":2}', "Two messages in one line"),
            (b'{"jsonrpc":"2.0","id":1}\r\n{"jsonrpc":"2.0","method":"steal","id":2}', "CRLF injection"),
            (b'{"jsonrpc":"2.0","id":1}\x00{"jsonrpc":"2.0","method":"steal","id":2}', "Null byte delimiter"),
            (b'{"jsonrpc":"2.0","method":"test","id":1}' + b'\n' * 10000, "Newline flood"),
            (b'\n' * 10000 + b'{"jsonrpc":"2.0","method":"test","id":1}', "Leading newline flood"),
            (b'{"jsonrpc":"2.0","method":"te\nst","id":1}', "Newline inside method"),
            (b'Content-Length: 10\r\n\r\n{"jsonrpc"\r\nContent-Length: 50\r\n\r\n{"jsonrpc":"2.0","method":"smuggled","id":1}', "HTTP request smuggling"),
        ]

        for i, (payload, desc) in enumerate(payloads):
            self._cases.append(TransportFuzzCase(
                case_id=f"delimiter_{i:03d}",
                category=FuzzCategory.DELIMITER_INJECTION,
                transport=TransportType.STDIO,
                description=desc,
                payload=payload,
            ))

    # ── SSE abuse ────────────────────────────────────────────────────

    def _gen_sse_abuse(self) -> None:
        payloads = [
            (b"data: \n\n", "Empty SSE data"),
            (b"data: " + b"A" * 1048576 + b"\n\n", "1MB SSE event"),
            (b"event: message\ndata: {}\n\n" * 10000, "10K rapid SSE events"),
            (b"data: {\"jsonrpc\":\"2.0\"}\ndata: {\"method\":\"inject\"}\n\n", "Multi-line data injection"),
            (b": comment\ndata: {\"jsonrpc\":\"2.0\"}\n\n", "SSE comment before data"),
            (b"id: 999999\ndata: {\"steal\": true}\n\n", "High SSE ID jump"),
            (b"retry: 0\ndata: {\"reconnect_flood\": true}\n\n", "Zero retry reconnect"),
            (b"retry: 1\ndata: test\n\n" * 1000, "Reconnect loop attack"),
            (b"event: error\ndata: {\"crash\": true}\n\n", "Fake error event"),
            (b"data: incomplete", "Unterminated SSE event"),
            (b"\n\n\n\n\n", "Empty newlines only"),
            (b"data: {\"jsonrpc\":\"2.0\"}" + b"\n" * 0 + b"data: {\"injected\":true}\n\n", "Missing double newline"),
        ]

        for i, (payload, desc) in enumerate(payloads):
            self._cases.append(TransportFuzzCase(
                case_id=f"sse_{i:03d}",
                category=FuzzCategory.SSE_ABUSE,
                transport=TransportType.SSE,
                description=desc,
                payload=payload,
            ))

    # ── Header injection ─────────────────────────────────────────────

    def _gen_header_injection(self) -> None:
        payloads = [
            (b"Content-Type: text/html\r\n\r\n<script>alert(1)</script>", "Content-Type XSS"),
            (b"Content-Type: application/json\r\nX-Injected: true\r\n\r\n{}", "Extra header injection"),
            (b"Content-Type: application/json\r\nHost: evil.com\r\n\r\n{}", "Host header override"),
            (b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n", "Chunked encoding with zero chunk"),
            (b"Content-Type: application/json\r\nAuthorization: Bearer stolen\r\n\r\n{}", "Auth header injection"),
            (b"Content-Type: application/json\r\n\r\n\r\n{}", "Double CRLF body separator"),
        ]

        for i, (payload, desc) in enumerate(payloads):
            self._cases.append(TransportFuzzCase(
                case_id=f"header_{i:03d}",
                category=FuzzCategory.HEADER_INJECTION,
                transport=TransportType.HTTP,
                description=desc,
                payload=payload,
            ))

    # ── Concurrent abuse ─────────────────────────────────────────────

    def _gen_concurrent_abuse(self) -> None:
        msg = json.dumps({"jsonrpc": "2.0", "method": "tools/list", "id": 1}).encode()
        patterns = [
            (b"\n".join([msg] * 100), "100 simultaneous requests same ID"),
            (b"\n".join([
                json.dumps({"jsonrpc": "2.0", "method": "tools/list", "id": i}).encode()
                for i in range(1000)
            ]), "1000 sequential requests"),
            (b"\n".join([
                json.dumps({"jsonrpc": "2.0", "method": "tools/call", "params": {"name": f"tool_{i}"}, "id": i}).encode()
                for i in range(100)
            ]), "100 parallel tool calls"),
        ]

        for i, (payload, desc) in enumerate(patterns):
            self._cases.append(TransportFuzzCase(
                case_id=f"concurrent_{i:03d}",
                category=FuzzCategory.CONCURRENT_ABUSE,
                transport=TransportType.STDIO,
                description=desc,
                payload=payload,
            ))

    # ── Protocol downgrade ───────────────────────────────────────────

    def _gen_protocol_downgrade(self) -> None:
        payloads = [
            (json.dumps({"jsonrpc": "1.0", "method": "test", "id": 1}).encode(), "JSON-RPC 1.0 downgrade"),
            (json.dumps({"jsonrpc": "3.0", "method": "test", "id": 1}).encode(), "JSON-RPC 3.0 upgrade"),
            (json.dumps({"jsonrpc": "2.0", "method": "initialize", "params": {"protocolVersion": "2020-01-01"}, "id": 1}).encode(), "Old MCP protocol version"),
            (json.dumps({"jsonrpc": "2.0", "method": "initialize", "params": {"protocolVersion": "9999-12-31"}, "id": 1}).encode(), "Future protocol version"),
            (b"<?xml version=\"1.0\"?><methodCall><methodName>test</methodName></methodCall>", "XML-RPC injection"),
            (b"CONNECT evil.com:443 HTTP/1.1\r\n\r\n", "HTTP CONNECT smuggling"),
        ]

        for i, (payload, desc) in enumerate(payloads):
            self._cases.append(TransportFuzzCase(
                case_id=f"downgrade_{i:03d}",
                category=FuzzCategory.PROTOCOL_DOWNGRADE,
                transport=TransportType.STDIO,
                description=desc,
                payload=payload,
            ))

    # ── Resource exhaustion ──────────────────────────────────────────

    def _gen_resource_exhaustion(self) -> None:
        payloads = [
            (json.dumps({
                "jsonrpc": "2.0", "method": "tools/call", "id": 1,
                "params": {"name": "test", "arguments": {f"key_{i}": "x" * 1000 for i in range(1000)}},
            }).encode(), "1K params with 1KB values each"),
            (b'{"jsonrpc":"2.0","method":"' + b"A" * 100000 + b'","id":1}', "100KB method name"),
            (json.dumps({
                "jsonrpc": "2.0", "method": "tools/call", "id": 1,
                "params": {"name": "test", "arguments": {"regex": "(a+)+$" * 100}},
            }).encode(), "ReDoS pattern in arguments"),
        ]

        for i, (payload, desc) in enumerate(payloads):
            self._cases.append(TransportFuzzCase(
                case_id=f"resource_{i:03d}",
                category=FuzzCategory.RESOURCE_EXHAUSTION,
                transport=TransportType.STDIO,
                description=desc,
                payload=payload,
            ))

    def get_summary(self) -> dict:
        by_category: dict[str, int] = {}
        by_transport: dict[str, int] = {}
        for c in self._cases:
            by_category[c.category.name] = by_category.get(c.category.name, 0) + 1
            by_transport[c.transport.name] = by_transport.get(c.transport.name, 0) + 1
        return {
            "total_cases": len(self._cases),
            "by_category": by_category,
            "by_transport": by_transport,
        }
