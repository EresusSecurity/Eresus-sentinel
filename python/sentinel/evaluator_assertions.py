"""Missing assertion types — context faithfulness, recall, G-Eval, moderation, trajectory, trace spans, etc."""

from __future__ import annotations

import json
import re
from typing import Any


def context_faithfulness_score(output: str, context: str) -> float:
    """Score how faithful output is to provided context (no hallucinated facts)."""
    if not output or not context:
        return 0.0
    output_sentences = [s.strip() for s in re.split(r'[.!?]+', output) if s.strip()]
    if not output_sentences:
        return 1.0
    context_lower = context.lower()
    supported = sum(
        1 for s in output_sentences
        if any(w in context_lower for w in s.lower().split() if len(w) > 3)
    )
    return supported / len(output_sentences)


def context_recall_score(reference: str, context: str) -> float:
    """Score how much of reference answer is recoverable from context."""
    if not reference or not context:
        return 0.0
    ref_sentences = [s.strip() for s in re.split(r'[.!?]+', reference) if s.strip()]
    if not ref_sentences:
        return 1.0
    context_lower = context.lower()
    recalled = sum(
        1 for s in ref_sentences
        if any(w in context_lower for w in s.lower().split() if len(w) > 3)
    )
    return recalled / len(ref_sentences)


def geval_score(output: str, criteria: str, reference: str = "") -> float:
    """G-Eval style scoring using NLI heuristics (no LLM call)."""
    score = 0.5
    if not output.strip():
        return 0.0
    word_count = len(output.split())
    if word_count < 5:
        score -= 0.2
    elif word_count > 20:
        score += 0.1
    criteria_lower = criteria.lower()
    if "coherence" in criteria_lower:
        sentences = re.split(r'[.!?]+', output)
        if len(sentences) > 1:
            score += 0.2
    if "relevance" in criteria_lower and reference:
        ref_words = set(reference.lower().split())
        out_words = set(output.lower().split())
        overlap = len(ref_words & out_words) / max(len(ref_words), 1)
        score += overlap * 0.3
    if "fluency" in criteria_lower:
        if output[0].isupper() and output.rstrip()[-1] in '.!?':
            score += 0.2
    return min(1.0, max(0.0, score))


def moderation_score(text: str) -> dict[str, float]:
    """Local moderation scoring (keyword-based, no API call)."""
    categories = {
        "hate": ["hate", "slur", "racist", "bigot", "supremac"],
        "violence": ["kill", "murder", "attack", "weapon", "bomb", "shoot"],
        "sexual": ["explicit", "pornograph", "nude", "sexual content"],
        "self_harm": ["suicide", "self-harm", "cut myself", "end my life"],
        "harassment": ["harass", "bully", "stalk", "threaten", "intimidat"],
    }
    text_lower = text.lower()
    scores: dict[str, float] = {}
    for cat, keywords in categories.items():
        hits = sum(1 for k in keywords if k in text_lower)
        scores[cat] = min(1.0, hits * 0.3)
    scores["flagged"] = max(scores.values())
    return scores


def search_rubric_score(output: str, query: str, expected_facts: list[str] | None = None) -> float:
    """Score search result quality against query and expected facts."""
    if not output:
        return 0.0
    score = 0.0
    query_words = set(query.lower().split())
    out_lower = output.lower()
    query_coverage = sum(1 for w in query_words if w in out_lower and len(w) > 2)
    score += (query_coverage / max(len(query_words), 1)) * 0.4
    if expected_facts:
        fact_hits = sum(1 for f in expected_facts if f.lower() in out_lower)
        score += (fact_hits / len(expected_facts)) * 0.6
    else:
        score += 0.3 if len(output.split()) > 20 else 0.1
    return min(1.0, score)


def tool_call_f1(predicted_calls: list[dict], expected_calls: list[dict]) -> dict[str, float]:
    """Compute F1 score for tool/function call predictions."""
    if not expected_calls and not predicted_calls:
        return {"precision": 1.0, "recall": 1.0, "f1": 1.0}
    if not predicted_calls:
        return {"precision": 0.0, "recall": 0.0, "f1": 0.0}
    if not expected_calls:
        return {"precision": 0.0, "recall": 0.0, "f1": 0.0}

    def _call_key(c: dict) -> str:
        name = c.get("name", c.get("function", ""))
        args = json.dumps(c.get("arguments", c.get("args", {})), sort_keys=True)
        return f"{name}:{args}"

    pred_keys = {_call_key(c) for c in predicted_calls}
    exp_keys = {_call_key(c) for c in expected_calls}
    tp = len(pred_keys & exp_keys)
    precision = tp / len(pred_keys) if pred_keys else 0.0
    recall = tp / len(exp_keys) if exp_keys else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    return {"precision": precision, "recall": recall, "f1": f1}


def trajectory_score(
    steps: list[dict[str, Any]],
    expected_steps: list[str] | None = None,
) -> float:
    """Score agent trajectory quality."""
    if not steps:
        return 0.0
    score = 0.0
    has_tool_calls = any(s.get("tool_call") or s.get("action") for s in steps)
    has_observations = any(s.get("observation") or s.get("result") for s in steps)
    has_final = any(s.get("final_answer") or s.get("output") for s in steps)
    if has_tool_calls:
        score += 0.3
    if has_observations:
        score += 0.3
    if has_final:
        score += 0.2
    if expected_steps:
        step_names = [s.get("action", s.get("tool_call", "")) for s in steps]
        matched = sum(1 for e in expected_steps if any(e.lower() in str(sn).lower() for sn in step_names))
        score += (matched / len(expected_steps)) * 0.2
    else:
        score += 0.1
    unique_actions = len({s.get("action", s.get("tool_call", "")) for s in steps})
    if unique_actions > 1:
        score += 0.1
    return min(1.0, score)


def trace_error_spans(spans: list[dict]) -> list[dict]:
    """Find error spans in a trace."""
    return [
        s for s in spans
        if s.get("status", "").lower() in ("error", "failed")
        or s.get("error")
        or s.get("status_code", 200) >= 400
    ]


def trace_span_count(spans: list[dict], filter_name: str = "") -> int:
    """Count spans, optionally filtered by name pattern."""
    if not filter_name:
        return len(spans)
    return sum(1 for s in spans if filter_name.lower() in s.get("name", "").lower())


def trace_span_duration(spans: list[dict]) -> dict[str, float]:
    """Compute duration statistics across spans."""
    durations = []
    for s in spans:
        d = s.get("duration_ms") or s.get("duration")
        if d is not None:
            durations.append(float(d))
    if not durations:
        return {"min": 0, "max": 0, "mean": 0, "p95": 0}
    durations.sort()
    p95_idx = int(len(durations) * 0.95)
    return {
        "min": durations[0],
        "max": durations[-1],
        "mean": sum(durations) / len(durations),
        "p95": durations[min(p95_idx, len(durations) - 1)],
    }


def html_assertion(text: str, selector: str = "", contains: str = "") -> bool:
    """Basic HTML content assertion."""
    if selector:
        pattern = rf'<{selector}[^>]*>(.*?)</{selector}>'
        matches = re.findall(pattern, text, re.DOTALL | re.IGNORECASE)
        if contains:
            return any(contains.lower() in m.lower() for m in matches)
        return len(matches) > 0
    if contains:
        return contains.lower() in text.lower()
    return bool(re.search(r'<[^>]+>', text))


def xml_assertion(text: str, xpath_tag: str = "", contains: str = "") -> bool:
    """Basic XML content assertion."""
    if xpath_tag:
        pattern = rf'<{xpath_tag}[^>]*>(.*?)</{xpath_tag}>'
        matches = re.findall(pattern, text, re.DOTALL)
        if contains:
            return any(contains.lower() in m.lower() for m in matches)
        return len(matches) > 0
    try:
        if text.strip().startswith('<'):
            return True
    except Exception:
        pass
    return False


def webhook_assertion(response: dict, expected_status: int = 200, expected_body: str = "") -> bool:
    """Assert webhook response meets expectations."""
    status = response.get("status_code", response.get("status", 0))
    if status != expected_status:
        return False
    if expected_body:
        body = response.get("body", response.get("text", ""))
        return expected_body.lower() in str(body).lower()
    return True


def guardrails_assertion(output: str, rules: list[dict[str, str]]) -> dict[str, bool]:
    """Check output against a list of guardrail rules."""
    results: dict[str, bool] = {}
    output_lower = output.lower()
    for rule in rules:
        name = rule.get("name", "unnamed")
        rule_type = rule.get("type", "contains")
        value = rule.get("value", "")
        if rule_type == "not_contains":
            results[name] = value.lower() not in output_lower
        elif rule_type == "contains":
            results[name] = value.lower() in output_lower
        elif rule_type == "regex":
            results[name] = bool(re.search(value, output, re.IGNORECASE))
        elif rule_type == "max_length":
            results[name] = len(output) <= int(value)
        elif rule_type == "min_length":
            results[name] = len(output) >= int(value)
        else:
            results[name] = True
    return results
