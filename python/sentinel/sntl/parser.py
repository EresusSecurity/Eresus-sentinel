from __future__ import annotations

import json
import re
from typing import Any

from sentinel.sntl.types import SntlParseError, SntlToken


_NUMBER_RE = re.compile(r"^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?$")
_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.:-]*$")


def parse(text: str) -> Any:
    tokens = _tokenize(text)
    if not tokens:
        return {}
    parser = _BlockParser(tokens)
    value = parser.parse_block(tokens[0].indent)
    if parser.index != len(tokens):
        token = tokens[parser.index]
        raise SntlParseError("unexpected trailing content", token.line, token.indent + 1)
    return value


def parse_document(text: str) -> dict[str, Any]:
    value = parse(text)
    if not isinstance(value, dict):
        raise SntlParseError("document root must be an object")
    return value


def _tokenize(text: str) -> list[SntlToken]:
    tokens: list[SntlToken] = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        if lineno == 1:
            raw = raw.lstrip("\ufeff")
        if "\t" in raw[: len(raw) - len(raw.lstrip())]:
            raise SntlParseError("tabs are not allowed for indentation", lineno, 1)
        stripped = raw.strip()
        if not stripped or stripped == "---" or stripped == "...":
            continue
        if stripped.startswith("%sntl"):
            continue
        line = _strip_comment(raw.rstrip())
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        tokens.append(SntlToken(lineno, indent, line.strip()))
    return tokens


def _strip_comment(line: str) -> str:
    quote: str | None = None
    escape = False
    depth = 0
    out: list[str] = []
    for ch in line:
        if quote:
            out.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = None
            continue
        if ch in {"'", '"'}:
            quote = ch
            out.append(ch)
            continue
        if ch in "[{(":
            depth += 1
        elif ch in "]})" and depth:
            depth -= 1
        if ch == "#" and depth == 0:
            break
        out.append(ch)
    return "".join(out).rstrip()


class _BlockParser:
    def __init__(self, tokens: list[SntlToken]):
        self.tokens = tokens
        self.index = 0

    def parse_block(self, indent: int) -> Any:
        token = self._peek()
        if token is None:
            return {}
        if token.indent < indent:
            return {}
        if token.indent > indent:
            raise SntlParseError("unexpected indentation", token.line, token.indent + 1)
        if token.text.startswith("- "):
            return self._parse_list(indent)
        return self._parse_map(indent)

    def _parse_map(self, indent: int) -> dict[str, Any]:
        result: dict[str, Any] = {}
        while self.index < len(self.tokens):
            token = self._peek()
            if token is None or token.indent < indent:
                break
            if token.indent > indent:
                raise SntlParseError("unexpected nested mapping", token.line, token.indent + 1)
            if token.text.startswith("- "):
                break
            key, rest = _split_key_value(token.text, token)
            if key in result:
                raise SntlParseError(f"duplicate key {key}", token.line, token.indent + 1)
            self.index += 1
            if rest == "":
                result[key] = self._parse_child_or_empty(indent)
            elif rest in {"|", ">"}:
                result[key] = self._parse_block_string(indent, rest)
            else:
                result[key] = parse_scalar(rest, token.line, token.indent + len(key) + 2)
            child = self._peek()
            if child is not None and child.indent > indent and rest not in {"", "|", ">"}:
                raise SntlParseError("scalar values cannot have nested children", child.line, child.indent + 1)
        return result

    def _parse_list(self, indent: int) -> list[Any]:
        result: list[Any] = []
        while self.index < len(self.tokens):
            token = self._peek()
            if token is None or token.indent < indent:
                break
            if token.indent > indent:
                raise SntlParseError("unexpected nested list item", token.line, token.indent + 1)
            if not token.text.startswith("- "):
                break
            item = token.text[2:].strip()
            self.index += 1
            if item == "":
                result.append(self._parse_child_or_empty(indent))
                continue
            split = _try_split_key_value(item)
            if split is not None:
                key, rest = split
                value: dict[str, Any] = {}
                value[key] = self._parse_child_or_empty(indent) if rest == "" else parse_scalar(rest, token.line, token.indent + 3)
                child = self._peek()
                if child is not None and child.indent > indent:
                    nested = self.parse_block(child.indent)
                    if not isinstance(nested, dict):
                        raise SntlParseError("list item extension must be an object", child.line, child.indent + 1)
                    for nested_key, nested_value in nested.items():
                        if nested_key in value:
                            raise SntlParseError(f"duplicate key {nested_key}", child.line, child.indent + 1)
                        value[nested_key] = nested_value
                result.append(value)
            else:
                result.append(parse_scalar(item, token.line, token.indent + 3))
        return result

    def _parse_child_or_empty(self, parent_indent: int) -> Any:
        child = self._peek()
        if child is None:
            return {}
        if child.indent > parent_indent:
            return self.parse_block(child.indent)
        if child.indent == parent_indent and child.text.startswith("- "):
            return self.parse_block(child.indent)
        return {}

    def _parse_block_string(self, parent_indent: int, mode: str) -> str:
        lines: list[str] = []
        base_indent: int | None = None
        while self.index < len(self.tokens):
            token = self._peek()
            if token is None or token.indent <= parent_indent:
                break
            if base_indent is None:
                base_indent = token.indent
            lines.append(" " * max(token.indent - base_indent, 0) + token.text)
            self.index += 1
        if mode == ">":
            return " ".join(line.strip() for line in lines).strip()
        return "\n".join(lines) + ("\n" if lines else "")

    def _peek(self) -> SntlToken | None:
        if self.index >= len(self.tokens):
            return None
        return self.tokens[self.index]


def _split_key_value(text: str, token: SntlToken) -> tuple[str, str]:
    split = _try_split_key_value(text)
    if split is None:
        raise SntlParseError("expected key: value", token.line, token.indent + 1)
    return split


def _try_split_key_value(text: str) -> tuple[str, str] | None:
    quote: str | None = None
    escape = False
    depth = 0
    for idx, ch in enumerate(text):
        if quote:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = None
            continue
        if ch in {"'", '"'}:
            quote = ch
            continue
        if ch in "[{(":
            depth += 1
        elif ch in "]})" and depth:
            depth -= 1
        elif ch == ":" and depth == 0:
            key = text[:idx].strip()
            rest = text[idx + 1 :].strip()
            if not key or not (_KEY_RE.match(key) or _is_quoted(key)):
                return None
            return _unquote_key(key), rest
    return None


def parse_scalar(text: str, line: int = 0, column: int = 0) -> Any:
    text = text.strip()
    if text == "":
        return ""
    lowered = text.lower()
    if lowered in {"null", "none", "~"}:
        return None
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    if _NUMBER_RE.match(text):
        return float(text) if any(ch in text for ch in ".eE") else int(text)
    if text.startswith('"') or text.startswith("'"):
        return _parse_quoted(text, line, column)
    if text.startswith("["):
        return _InlineParser(text, line, column).parse_array()
    if text.startswith("{"):
        return _InlineParser(text, line, column).parse_object()
    return text


def _is_quoted(text: str) -> bool:
    return (text.startswith('"') and text.endswith('"')) or (text.startswith("'") and text.endswith("'"))


def _unquote_key(text: str) -> str:
    return str(_parse_quoted(text, 0, 0)) if _is_quoted(text) else text


def _parse_quoted(text: str, line: int, column: int) -> str:
    if text.startswith('"'):
        try:
            return str(json.loads(text))
        except json.JSONDecodeError as exc:
            raise SntlParseError(exc.msg, line, column + exc.pos) from exc
    if text.startswith("'") and text.endswith("'"):
        return text[1:-1].replace("\\'", "'").replace("\\\\", "\\")
    raise SntlParseError("unterminated quoted string", line, column)


class _InlineParser:
    def __init__(self, text: str, line: int, column: int):
        self.text = text
        self.line = line
        self.column = column
        self.index = 0

    def parse_array(self) -> list[Any]:
        self._expect("[")
        out: list[Any] = []
        self._space()
        if self._take("]"):
            return out
        while True:
            out.append(self._value())
            self._space()
            if self._take("]"):
                return out
            self._expect(",")

    def parse_object(self) -> dict[str, Any]:
        self._expect("{")
        out: dict[str, Any] = {}
        self._space()
        if self._take("}"):
            return out
        while True:
            key = self._key()
            self._space()
            self._expect(":")
            value = self._value()
            if key in out:
                raise SntlParseError(f"duplicate key {key}", self.line, self.column + self.index)
            out[key] = value
            self._space()
            if self._take("}"):
                return out
            self._expect(",")

    def _value(self) -> Any:
        self._space()
        ch = self._peek()
        if ch == "[":
            return self.parse_array()
        if ch == "{":
            return self.parse_object()
        if ch in {"'", '"'}:
            return self._quoted()
        start = self.index
        while self.index < len(self.text) and self.text[self.index] not in ",]}":
            self.index += 1
        raw = self.text[start : self.index].strip()
        if raw == "":
            raise SntlParseError("expected value", self.line, self.column + start)
        return parse_scalar(raw, self.line, self.column + start)

    def _key(self) -> str:
        self._space()
        if self._peek() in {"'", '"'}:
            return str(self._quoted())
        start = self.index
        while self.index < len(self.text) and self.text[self.index] not in ":":
            self.index += 1
        key = self.text[start : self.index].strip()
        if not key:
            raise SntlParseError("expected key", self.line, self.column + start)
        return key

    def _quoted(self) -> str:
        quote = self._peek()
        start = self.index
        self.index += 1
        escape = False
        while self.index < len(self.text):
            ch = self.text[self.index]
            self.index += 1
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                return _parse_quoted(self.text[start : self.index], self.line, self.column + start)
        raise SntlParseError("unterminated quoted string", self.line, self.column + start)

    def _space(self) -> None:
        while self.index < len(self.text) and self.text[self.index].isspace():
            self.index += 1

    def _peek(self) -> str:
        self._space()
        if self.index >= len(self.text):
            raise SntlParseError("unexpected end of inline value", self.line, self.column + self.index)
        return self.text[self.index]

    def _take(self, ch: str) -> bool:
        self._space()
        if self.index < len(self.text) and self.text[self.index] == ch:
            self.index += 1
            return True
        return False

    def _expect(self, ch: str) -> None:
        if not self._take(ch):
            raise SntlParseError(f"expected {ch}", self.line, self.column + self.index)
