"""LLM Consensus Judge — N-run majority voting for false-positive reduction.

Runs the same security classification prompt N times and takes a majority
vote to reduce LLM variance. If majority says True Positive → keep finding.
If majority says False Positive → suppress or downgrade.

Optionally uses multiple LLM providers for cross-model consensus.
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)

_CLASSIFY_PROMPT = """\
You are a security expert reviewing a scan finding for a production AI/LLM system.

Rule ID: {rule_id}
Title: {title}
Severity: {severity}
Description: {description}
Evidence: {evidence}
Target: {target}

Is this a TRUE POSITIVE (real security issue) or FALSE POSITIVE (noise/benign)?

Respond ONLY with valid JSON:
{{
  "verdict": "true_positive" | "false_positive" | "uncertain",
  "confidence": 0.0-1.0,
  "rationale": "one sentence"
}}
"""


@dataclass
class ConsensusVote:
    verdict: str
    confidence: float
    rationale: str
    provider: str
    run: int


@dataclass
class ConsensusResult:
    is_true_positive: bool
    confidence: float
    true_positive_votes: int
    false_positive_votes: int
    uncertain_votes: int
    total_runs: int
    votes: list[ConsensusVote] = field(default_factory=list)
    rationale: str = ""

    @property
    def vote_ratio(self) -> float:
        if self.total_runs == 0:
            return 0.0
        return self.true_positive_votes / self.total_runs


class LLMConsensusJudge:
    """N-run LLM majority-vote classifier for scan findings.

    Args:
        provider: LLM provider name (``openai``, ``anthropic``, ``ollama``).
        model: Model identifier.
        api_key: API key (falls back to env var).
        runs: Number of independent LLM calls per finding.
        threshold: Fraction of votes required to classify as TP (default 0.6).
        temperature: Sampling temperature — use > 0 for variance across runs.
        timeout: Per-call timeout in seconds.
    """

    def __init__(
        self,
        provider: str = "openai",
        model: str = "gpt-4o-mini",
        api_key: Optional[str] = None,
        runs: int = 3,
        threshold: float = 0.60,
        temperature: float = 0.3,
        timeout: int = 30,
    ) -> None:
        self._provider = provider
        self._model = model
        self._api_key = api_key or os.environ.get("OPENAI_API_KEY") or os.environ.get("ANTHROPIC_API_KEY")
        self._runs = max(1, runs)
        self._threshold = threshold
        self._temperature = temperature
        self._timeout = timeout
        self._client: Any = None

    def judge(self, finding: Any) -> ConsensusResult:
        """Run N LLM calls and aggregate by majority vote.

        Args:
            finding: Any object with rule_id, title, severity, description,
                     evidence, target attributes (e.g. sentinel.finding.Finding).

        Returns:
            ConsensusResult with is_true_positive and vote breakdown.
        """
        prompt = _CLASSIFY_PROMPT.format(
            rule_id=getattr(finding, "rule_id", "UNKNOWN"),
            title=getattr(finding, "title", ""),
            severity=getattr(finding, "severity", "MEDIUM"),
            description=getattr(finding, "description", "")[:500],
            evidence=str(getattr(finding, "evidence", ""))[:300],
            target=getattr(finding, "target", ""),
        )

        votes: list[ConsensusVote] = []
        for i in range(self._runs):
            vote = self._single_vote(prompt, run=i)
            votes.append(vote)
            logger.debug("Consensus run %d/%d: %s (%.2f)", i + 1, self._runs, vote.verdict, vote.confidence)

        tp_votes = sum(1 for v in votes if v.verdict == "true_positive")
        fp_votes = sum(1 for v in votes if v.verdict == "false_positive")
        un_votes = sum(1 for v in votes if v.verdict == "uncertain")

        is_tp = (tp_votes / self._runs) >= self._threshold

        avg_conf = sum(v.confidence for v in votes) / len(votes) if votes else 0.0

        best = max(votes, key=lambda v: v.confidence) if votes else None
        rationale = best.rationale if best else ""

        return ConsensusResult(
            is_true_positive=is_tp,
            confidence=round(avg_conf, 3),
            true_positive_votes=tp_votes,
            false_positive_votes=fp_votes,
            uncertain_votes=un_votes,
            total_runs=self._runs,
            votes=votes,
            rationale=rationale,
        )

    def judge_batch(self, findings: list[Any]) -> dict[str, ConsensusResult]:
        """Judge multiple findings, keyed by finding id or rule_id."""
        results = {}
        for f in findings:
            key = str(getattr(f, "id", getattr(f, "rule_id", id(f))))
            results[key] = self.judge(f)
        return results

    def filter_findings(
        self,
        findings: list[Any],
        *,
        suppress_fp: bool = True,
        annotate: bool = True,
    ) -> tuple[list[Any], list[Any]]:
        """Filter findings via consensus — return (kept, suppressed)."""
        kept: list[Any] = []
        suppressed: list[Any] = []

        for f in findings:
            result = self.judge(f)
            if result.is_true_positive or result.uncertain_votes == self._runs:
                if annotate and hasattr(f, "tags"):
                    f.tags.append(f"consensus:tp:{result.confidence:.2f}")
                kept.append(f)
            else:
                if annotate and hasattr(f, "tags"):
                    f.tags.append(f"consensus:fp:{result.confidence:.2f}")
                if suppress_fp:
                    suppressed.append(f)
                else:
                    kept.append(f)

        logger.info(
            "Consensus filter: %d kept, %d suppressed from %d",
            len(kept), len(suppressed), len(findings),
        )
        return kept, suppressed

    def _single_vote(self, prompt: str, *, run: int) -> ConsensusVote:
        """One LLM call → one vote."""
        client = self._get_client()
        if client is None:
            return ConsensusVote(
                verdict="uncertain",
                confidence=0.0,
                rationale="LLM provider unavailable",
                provider=self._provider,
                run=run,
            )
        try:
            raw = self._call_llm(client, prompt)
            return self._parse_vote(raw, run)
        except Exception as exc:
            logger.warning("Consensus vote %d failed: %s", run, exc)
            return ConsensusVote(
                verdict="uncertain",
                confidence=0.0,
                rationale=str(exc)[:120],
                provider=self._provider,
                run=run,
            )

    def _call_llm(self, client: Any, prompt: str) -> str:
        if hasattr(client, "generate"):
            return client.generate(prompt)
        if hasattr(client, "chat"):
            resp = client.chat.completions.create(
                model=self._model,
                messages=[{"role": "user", "content": prompt}],
                temperature=self._temperature,
                timeout=self._timeout,
            )
            return resp.choices[0].message.content or ""
        if hasattr(client, "messages"):
            resp = client.messages.create(
                model=self._model,
                max_tokens=256,
                messages=[{"role": "user", "content": prompt}],
            )
            return resp.content[0].text if resp.content else ""
        raise RuntimeError(f"Unknown client interface: {type(client)}")

    def _parse_vote(self, raw: str, run: int) -> ConsensusVote:
        try:
            start = raw.find("{")
            end = raw.rfind("}") + 1
            if start == -1 or end == 0:
                raise ValueError("No JSON in response")
            data = json.loads(raw[start:end])
            verdict = data.get("verdict", "uncertain")
            if verdict not in ("true_positive", "false_positive", "uncertain"):
                verdict = "uncertain"
            return ConsensusVote(
                verdict=verdict,
                confidence=float(data.get("confidence", 0.5)),
                rationale=str(data.get("rationale", ""))[:200],
                provider=self._provider,
                run=run,
            )
        except Exception as exc:
            return ConsensusVote(
                verdict="uncertain",
                confidence=0.3,
                rationale=f"parse error: {exc}",
                provider=self._provider,
                run=run,
            )

    def _get_client(self) -> Any:
        if self._client is not None:
            return self._client
        try:
            from sentinel.redteam.generators import get_generator
            self._client = get_generator(self._provider, model=self._model, api_key=self._api_key)
            return self._client
        except Exception:
            pass
        if self._provider == "openai":
            try:
                import openai
                self._client = openai.OpenAI(api_key=self._api_key)
                return self._client
            except ImportError:
                pass
        elif self._provider == "anthropic":
            try:
                import anthropic
                self._client = anthropic.Anthropic(api_key=self._api_key)
                return self._client
            except ImportError:
                pass
        return None
