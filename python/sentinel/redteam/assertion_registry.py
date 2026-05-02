"""Config-driven assertion registry for eval and redteam runs."""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)
NUMBER_TYPES = (int, float)


class AssertionStatus(str, Enum):
    PASS = "pass"  # noqa: S105
    FAIL = "fail"
    SKIP = "skip"
    ERROR = "error"


@dataclass
class AssertionResult:
    assertion_id: str
    status: AssertionStatus
    message: str = ""
    actual: Any = None
    expected: Any = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class AssertionSpec:
    id: str
    type: str  # "contains", "regex", "json_path", "tool_call", "custom"
    description: str = ""
    expected: Any = None
    negate: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


class AssertionRegistry:
    """Registry of assertion types and their evaluators."""

    def __init__(self) -> None:
        self._evaluators: dict[str, Callable] = {}
        self._register_builtins()

    def _register_builtins(self) -> None:
        self._register_aliases(("contains",), self._assert_contains)
        self._register_aliases(
            ("not_contains", "not-contains", "notContains"),
            self._assert_not_contains,
        )
        self._register_aliases(("regex", "matches"), self._assert_regex)
        self._register_aliases(("equals", "is-equal", "isEqual"), self._assert_equals)
        self._register_aliases(
            ("length_max", "length-max", "max_length", "maxLength"),
            self._assert_length_max,
        )
        self._register_aliases(("json_path", "json-path", "jsonPath"), self._assert_json_path)
        self._register_aliases(("json", "valid_json", "validJson"), self._assert_valid_json)
        self._register_aliases(
            ("starts_with", "starts-with", "startsWith"),
            self._assert_starts_with,
        )
        self._register_aliases(("word_count", "word-count", "wordCount"), self._assert_word_count)
        self._register_aliases(("similar", "similarity"), self._assert_similarity)
        self._register_aliases(("levenshtein",), self._assert_levenshtein)
        self._register_aliases(
            ("answer_relevance", "answer-relevance", "answerRelevance"),
            self._assert_answer_relevance,
        )
        self._register_aliases(
            ("context_faithfulness", "context-faithfulness", "contextFaithfulness"),
            self._assert_context_faithfulness,
        )
        self._register_aliases(
            ("context_recall", "context-recall", "contextRecall"),
            self._assert_context_recall,
        )
        self._register_aliases(
            ("context_relevance", "context-relevance", "contextRelevance"),
            self._assert_context_relevance,
        )
        self._register_aliases(
            ("geval", "g_eval", "g-eval", "llm_rubric", "llm-rubric", "llmRubric"),
            self._assert_geval,
        )
        self._register_aliases(
            ("moderation", "openai_moderation", "openai-moderation"),
            self._assert_moderation,
        )
        self._register_aliases(
            ("search_rubric", "search-rubric", "searchRubric"),
            self._assert_search_rubric,
        )
        self._register_aliases(
            ("tool_call_f1", "tool-call-f1", "toolCallF1", "functionToolCall"),
            self._assert_tool_call_f1,
        )
        self._register_aliases(
            ("trajectory", "agent_trajectory", "agent-trajectory"),
            self._assert_trajectory,
        )
        self._register_aliases(
            ("trace_error_spans", "trace-error-spans", "traceErrorSpans"),
            self._assert_trace_error_spans,
        )
        self._register_aliases(
            ("trace_span_count", "trace-span-count", "traceSpanCount"),
            self._assert_trace_span_count,
        )
        self._register_aliases(
            ("trace_span_duration", "trace-span-duration", "traceSpanDuration"),
            self._assert_trace_span_duration,
        )
        self._register_aliases(("html", "html_assertion", "html-assertion"), self._assert_html)
        self._register_aliases(("xml", "xml_assertion", "xml-assertion"), self._assert_xml)
        self._register_aliases(
            ("webhook", "webhook_assertion", "webhook-assertion"),
            self._assert_webhook,
        )
        self._register_aliases(
            ("guardrails", "guardrails_assertion", "guardrails-assertion"),
            self._assert_guardrails,
        )
        self._register_aliases(
            ("memorization", "memorization_score", "memorizationScore", "memorisation"),
            self._assert_memorization,
        )

    def _register_aliases(self, aliases: tuple[str, ...], evaluator: Callable) -> None:
        for alias in aliases:
            self._evaluators[alias] = evaluator

    def register(self, type_name: str, evaluator: Callable) -> None:
        self._evaluators[type_name] = evaluator

    def evaluate(self, spec: AssertionSpec, output: str) -> AssertionResult:
        evaluator = self._evaluators.get(spec.type)
        if not evaluator:
            return AssertionResult(
                assertion_id=spec.id,
                status=AssertionStatus.ERROR,
                message=f"Unknown assertion type: {spec.type}",
            )
        try:
            passed, msg = evaluator(output, spec.expected, spec.metadata)
            if spec.negate:
                passed = not passed
            return AssertionResult(
                assertion_id=spec.id,
                status=AssertionStatus.PASS if passed else AssertionStatus.FAIL,
                message=msg,
                actual=output[:200] if isinstance(output, str) else output,
                expected=spec.expected,
            )
        except Exception as e:
            return AssertionResult(
                assertion_id=spec.id,
                status=AssertionStatus.ERROR,
                message=str(e),
            )

    def evaluate_all(self, specs: list[AssertionSpec], output: str) -> list[AssertionResult]:
        return [self.evaluate(spec, output) for spec in specs]

    @property
    def type_count(self) -> int:
        return len(self._evaluators)

    @staticmethod
    def _assert_contains(output: str, expected: Any, _: dict) -> tuple[bool, str]:
        target = str(expected)
        found = target in output
        return found, f"Contains '{target}': {'found' if found else 'not found'}"

    @staticmethod
    def _assert_not_contains(output: str, expected: Any, _: dict) -> tuple[bool, str]:
        target = str(expected)
        found = target not in output
        return found, f"Not contains '{target}': {'absent' if found else 'present'}"

    @staticmethod
    def _assert_regex(output: str, expected: Any, _: dict) -> tuple[bool, str]:
        pattern = str(expected)
        match = bool(re.search(pattern, output))
        return match, f"Regex '{pattern}': {'matched' if match else 'no match'}"

    @staticmethod
    def _assert_equals(output: str, expected: Any, _: dict) -> tuple[bool, str]:
        target = str(expected)
        equal = output.strip() == target.strip()
        return equal, f"Equals: {'match' if equal else 'mismatch'}"

    @staticmethod
    def _assert_length_max(output: str, expected: Any, _: dict) -> tuple[bool, str]:
        max_len = int(expected)
        actual = len(output)
        ok = actual <= max_len
        return ok, f"Length {actual} {'<=' if ok else '>'} {max_len}"

    @staticmethod
    def _assert_json_path(output: str, expected: Any, meta: dict) -> tuple[bool, str]:
        try:
            data = json.loads(output)
        except Exception:
            return False, "Output is not valid JSON"
        path = str(meta.get("path", ""))
        parts = path.strip(".").split(".")
        current = data
        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return False, f"JSON path '{path}' not found"
        if expected is not None:
            return str(current) == str(expected), f"JSON path '{path}': {current}"
        return True, f"JSON path '{path}' exists: {current}"

    @staticmethod
    def _assert_valid_json(output: str, expected: Any, _: dict) -> tuple[bool, str]:
        try:
            data = json.loads(output)
        except Exception:
            return False, "Output is not valid JSON"
        if isinstance(expected, dict):
            required_keys = expected.get("required_keys") or expected.get("keys") or []
            missing = [
                key for key in required_keys if not isinstance(data, dict) or key not in data
            ]
            if missing:
                return False, f"JSON missing keys: {', '.join(map(str, missing))}"
        return True, "Output is valid JSON"

    @staticmethod
    def _assert_starts_with(output: str, expected: Any, _: dict) -> tuple[bool, str]:
        prefix = str(expected)
        ok = output.startswith(prefix)
        return ok, f"Starts with '{prefix}': {'yes' if ok else 'no'}"

    @staticmethod
    def _assert_word_count(output: str, expected: Any, meta: dict) -> tuple[bool, str]:
        words = len(re.findall(r"\S+", output))
        cfg = _merge_expected_meta(expected, meta)
        minimum = cfg.get("min", cfg.get("minimum"))
        default_max = (
            expected
            if isinstance(expected, (*NUMBER_TYPES, str)) and str(expected).isdigit()
            else None
        )
        maximum = cfg.get("max", cfg.get("maximum", default_max))
        if minimum is not None and words < int(minimum):
            return False, f"Word count {words} < {minimum}"
        if maximum is not None and words > int(maximum):
            return False, f"Word count {words} > {maximum}"
        return True, f"Word count {words} within bounds"

    @staticmethod
    def _assert_similarity(output: str, expected: Any, meta: dict) -> tuple[bool, str]:
        reference = str(expected or meta.get("reference", ""))
        score = _jaccard_similarity(output, reference)
        threshold = _threshold(expected, meta, default=0.7)
        return score >= threshold, _score_message("Similarity", score, threshold)

    @staticmethod
    def _assert_levenshtein(output: str, expected: Any, meta: dict) -> tuple[bool, str]:
        reference = str(expected or meta.get("reference", ""))
        distance = _levenshtein_distance(output, reference)
        maximum = int(meta.get("max_distance", meta.get("maximum", meta.get("max", 0))))
        return distance <= maximum, _limit_message("Levenshtein distance", distance, maximum)

    @staticmethod
    def _assert_answer_relevance(output: str, expected: Any, meta: dict) -> tuple[bool, str]:
        query = str(meta.get("query") or meta.get("prompt") or expected or "")
        score = _jaccard_similarity(output, query)
        threshold = _threshold(expected, meta, default=0.3)
        return score >= threshold, _score_message("Answer relevance", score, threshold)

    @staticmethod
    def _assert_context_faithfulness(output: str, expected: Any, meta: dict) -> tuple[bool, str]:
        from sentinel.evaluator_assertions import context_faithfulness_score

        cfg = _merge_expected_meta(expected, meta)
        context = cfg.get("context") or (expected if isinstance(expected, str) else "")
        score = context_faithfulness_score(output, str(context))
        threshold = _threshold(expected, meta, default=0.7)
        return score >= threshold, _score_message("Context faithfulness", score, threshold)

    @staticmethod
    def _assert_context_recall(output: str, expected: Any, meta: dict) -> tuple[bool, str]:
        from sentinel.evaluator_assertions import context_recall_score

        cfg = _merge_expected_meta(expected, meta)
        reference = str(cfg.get("reference") or cfg.get("answer") or output)
        context = str(cfg.get("context", ""))
        score = context_recall_score(reference, context)
        threshold = _threshold(expected, meta, default=0.7)
        return score >= threshold, _score_message("Context recall", score, threshold)

    @staticmethod
    def _assert_context_relevance(output: str, expected: Any, meta: dict) -> tuple[bool, str]:
        cfg = _merge_expected_meta(expected, meta)
        context = str(cfg.get("context") or (expected if isinstance(expected, str) else ""))
        score = _jaccard_similarity(output, context)
        threshold = _threshold(expected, meta, default=0.3)
        return score >= threshold, _score_message("Context relevance", score, threshold)

    @staticmethod
    def _assert_geval(output: str, expected: Any, meta: dict) -> tuple[bool, str]:
        from sentinel.evaluator_assertions import geval_score

        cfg = _merge_expected_meta(expected, meta)
        criteria = str(cfg.get("criteria") or cfg.get("rubric") or expected or "relevance")
        reference = str(cfg.get("reference", ""))
        score = geval_score(output, criteria, reference)
        threshold = _threshold(expected, meta, default=0.6)
        return score >= threshold, _score_message("G-Eval score", score, threshold)

    @staticmethod
    def _assert_moderation(output: str, expected: Any, meta: dict) -> tuple[bool, str]:
        from sentinel.evaluator_assertions import moderation_score

        scores = moderation_score(output)
        limit = float(
            _merge_expected_meta(expected, meta).get("max_score", meta.get("threshold", 0.29))
        )
        flagged = float(scores.get("flagged", 0.0))
        return flagged <= limit, _limit_message("Moderation flagged", flagged, limit)

    @staticmethod
    def _assert_search_rubric(output: str, expected: Any, meta: dict) -> tuple[bool, str]:
        from sentinel.evaluator_assertions import search_rubric_score

        cfg = _merge_expected_meta(expected, meta)
        query = str(cfg.get("query") or (expected if isinstance(expected, str) else ""))
        score = search_rubric_score(output, query, cfg.get("expected_facts"))
        threshold = _threshold(expected, meta, default=0.6)
        return score >= threshold, _score_message("Search rubric", score, threshold)

    @staticmethod
    def _assert_tool_call_f1(output: str, expected: Any, meta: dict) -> tuple[bool, str]:
        from sentinel.evaluator_assertions import tool_call_f1

        predicted = meta.get("predicted_calls", _json_or_value(output))
        if isinstance(predicted, dict):
            predicted = predicted.get("tool_calls") or predicted.get("calls") or [predicted]
        expected_calls = expected if isinstance(expected, list) else meta.get("expected_calls", [])
        scores = tool_call_f1(
            predicted if isinstance(predicted, list) else [],
            expected_calls if isinstance(expected_calls, list) else [],
        )
        threshold = _threshold(expected, meta, default=0.8)
        return scores["f1"] >= threshold, _score_message("Tool-call F1", scores["f1"], threshold)

    @staticmethod
    def _assert_trajectory(output: str, expected: Any, meta: dict) -> tuple[bool, str]:
        from sentinel.evaluator_assertions import trajectory_score

        parsed = _json_or_value(output)
        steps = (
            parsed.get("steps", parsed.get("trajectory", []))
            if isinstance(parsed, dict)
            else parsed
        )
        expected_steps = expected if isinstance(expected, list) else meta.get("expected_steps")
        score = trajectory_score(steps if isinstance(steps, list) else [], expected_steps)
        threshold = _threshold(expected, meta, default=0.7)
        return score >= threshold, _score_message("Trajectory score", score, threshold)

    @staticmethod
    def _assert_trace_error_spans(output: str, expected: Any, meta: dict) -> tuple[bool, str]:
        from sentinel.evaluator_assertions import trace_error_spans

        spans = _extract_spans(output)
        errors = trace_error_spans(spans)
        maximum = int(_merge_expected_meta(expected, meta).get("max_errors", 0))
        return len(errors) <= maximum, _limit_message("Trace error spans", len(errors), maximum)

    @staticmethod
    def _assert_trace_span_count(output: str, expected: Any, meta: dict) -> tuple[bool, str]:
        from sentinel.evaluator_assertions import trace_span_count

        cfg = _merge_expected_meta(expected, meta)
        count = trace_span_count(_extract_spans(output), str(cfg.get("filter_name", "")))
        minimum = cfg.get("min")
        maximum = cfg.get("max", expected if isinstance(expected, int | float) else None)
        if minimum is not None and count < int(minimum):
            return False, f"Trace span count {count} < {minimum}"
        if maximum is not None and count > int(maximum):
            return False, f"Trace span count {count} > {maximum}"
        return True, f"Trace span count {count} within bounds"

    @staticmethod
    def _assert_trace_span_duration(output: str, expected: Any, meta: dict) -> tuple[bool, str]:
        from sentinel.evaluator_assertions import trace_span_duration

        stats = trace_span_duration(_extract_spans(output))
        cfg = _merge_expected_meta(expected, meta)
        metric = str(cfg.get("metric", "p95"))
        default_max = expected if isinstance(expected, NUMBER_TYPES) else 1000
        maximum = float(cfg.get("max", cfg.get("maximum", default_max)))
        value = float(stats.get(metric, 0.0))
        return value <= maximum, _limit_message(f"Trace {metric} duration", value, maximum, "ms")

    @staticmethod
    def _assert_html(output: str, expected: Any, meta: dict) -> tuple[bool, str]:
        from sentinel.evaluator_assertions import html_assertion

        cfg = _merge_expected_meta(expected, meta)
        ok = html_assertion(
            output,
            str(cfg.get("selector", "")),
            str(cfg.get("contains", expected if isinstance(expected, str) else "")),
        )
        return ok, f"HTML assertion {'passed' if ok else 'failed'}"

    @staticmethod
    def _assert_xml(output: str, expected: Any, meta: dict) -> tuple[bool, str]:
        from sentinel.evaluator_assertions import xml_assertion

        cfg = _merge_expected_meta(expected, meta)
        ok = xml_assertion(
            output,
            str(cfg.get("xpath_tag", cfg.get("tag", ""))),
            str(cfg.get("contains", expected if isinstance(expected, str) else "")),
        )
        return ok, f"XML assertion {'passed' if ok else 'failed'}"

    @staticmethod
    def _assert_webhook(output: str, expected: Any, meta: dict) -> tuple[bool, str]:
        from sentinel.evaluator_assertions import webhook_assertion

        response = _json_or_value(output)
        cfg = _merge_expected_meta(expected, meta)
        ok = webhook_assertion(
            response if isinstance(response, dict) else {},
            int(cfg.get("status", cfg.get("expected_status", 200))),
            str(cfg.get("body", cfg.get("expected_body", ""))),
        )
        return ok, f"Webhook assertion {'passed' if ok else 'failed'}"

    @staticmethod
    def _assert_memorization(output: str, expected: Any, meta: dict) -> tuple[bool, str]:
        from sentinel.evaluator_assertions import memorization_score

        cfg = _merge_expected_meta(expected, meta)
        seed = str(cfg.get("seed") or cfg.get("prefix") or (expected if isinstance(expected, str) else ""))
        corpus = cfg.get("corpus") or cfg.get("reference_corpus")
        score = memorization_score(output, seed, corpus if isinstance(corpus, list) else None)
        # For memorization we invert: pass = low score (no leak), fail = high score (leak detected)
        max_score = float(cfg.get("max_score", cfg.get("threshold", 0.5)))
        ok = score <= max_score
        return ok, f"Memorization score {score:.2f} {'<=' if ok else '>'} {max_score:.2f}"

    @staticmethod
    def _assert_guardrails(output: str, expected: Any, meta: dict) -> tuple[bool, str]:
        from sentinel.evaluator_assertions import guardrails_assertion

        rules = expected if isinstance(expected, list) else meta.get("rules", [])
        results = guardrails_assertion(output, rules if isinstance(rules, list) else [])
        failed = [name for name, passed in results.items() if not passed]
        message = "Guardrails passed" if not failed else f"Guardrails failed: {', '.join(failed)}"
        return not failed, message


def _merge_expected_meta(expected: Any, meta: dict) -> dict[str, Any]:
    cfg: dict[str, Any] = {}
    if isinstance(expected, dict):
        cfg.update(expected)
    cfg.update(meta or {})
    return cfg


def _threshold(expected: Any, meta: dict, default: float) -> float:
    if isinstance(expected, dict) and "threshold" in expected:
        return float(expected["threshold"])
    if "threshold" in meta:
        return float(meta["threshold"])
    if isinstance(expected, NUMBER_TYPES):
        return float(expected)
    return default


def _score_message(label: str, score: float, threshold: float) -> str:
    operator = ">=" if score >= threshold else "<"
    return f"{label} {score:.2f} {operator} {threshold:.2f}"


def _limit_message(label: str, value: float, limit: float, suffix: str = "") -> str:
    operator = "<=" if value <= limit else ">"
    rendered_value = f"{value:.1f}{suffix}" if isinstance(value, float) else f"{value}{suffix}"
    rendered_limit = f"{limit:.1f}{suffix}" if isinstance(limit, float) else f"{limit}{suffix}"
    return f"{label} {rendered_value} {operator} {rendered_limit}"


def _json_or_value(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except Exception:
        return value


def _extract_spans(output: str) -> list[dict]:
    parsed = _json_or_value(output)
    if isinstance(parsed, dict):
        spans = parsed.get("spans", parsed.get("trace", []))
        return spans if isinstance(spans, list) else []
    return parsed if isinstance(parsed, list) else []


def _jaccard_similarity(left: str, right: str) -> float:
    left_terms = {term.lower() for term in re.findall(r"\w+", left) if len(term) > 2}
    right_terms = {term.lower() for term in re.findall(r"\w+", right) if len(term) > 2}
    if not left_terms and not right_terms:
        return 1.0
    if not left_terms or not right_terms:
        return 0.0
    return len(left_terms & right_terms) / len(left_terms | right_terms)


def _levenshtein_distance(left: str, right: str) -> int:
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)
    previous = list(range(len(right) + 1))
    for i, left_char in enumerate(left, 1):
        current = [i]
        for j, right_char in enumerate(right, 1):
            current.append(
                min(
                    previous[j] + 1,
                    current[j - 1] + 1,
                    previous[j - 1] + (left_char != right_char),
                )
            )
        previous = current
    return previous[-1]
