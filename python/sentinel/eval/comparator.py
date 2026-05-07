"""Prompt-level multi-provider side-by-side comparator.

Runs the same prompts against multiple LLM providers and scores responses
using configurable assertions. Produces a comparison matrix and HTML/JSON report.

Features:
  - Multiple providers in one run
  - Per-prompt side-by-side scoring
  - Pluggable assertion functions (exact, contains, regex, llm-judge)
  - Export: JSON, HTML, CSV
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


@dataclass
class ProviderConfig:
    name: str
    provider: str  # "openai", "anthropic", "ollama", "azure", "bedrock"
    model: str
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    extra: dict = field(default_factory=dict)


@dataclass
class PromptCase:
    prompt: str
    id: str = ""
    description: str = ""
    assert_fn: Optional[Callable[[str], tuple[bool, float]]] = None
    tags: list[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.id:
            import hashlib
            self.id = hashlib.sha256(self.prompt.encode()).hexdigest()[:8]


@dataclass
class ProviderResponse:
    provider_name: str
    response: str
    latency_ms: float
    passed: bool
    score: float
    error: Optional[str] = None


@dataclass
class PromptResult:
    case_id: str
    prompt: str
    responses: dict[str, ProviderResponse] = field(default_factory=dict)

    @property
    def best_provider(self) -> Optional[str]:
        if not self.responses:
            return None
        return max(self.responses, key=lambda k: self.responses[k].score)

    @property
    def pass_rate(self) -> float:
        if not self.responses:
            return 0.0
        passed = sum(1 for r in self.responses.values() if r.passed)
        return passed / len(self.responses)


@dataclass
class ComparisonReport:
    providers: list[str]
    results: list[PromptResult]
    generated_at: str = ""

    @property
    def overall_pass_rates(self) -> dict[str, float]:
        rates: dict[str, list[bool]] = {p: [] for p in self.providers}
        for result in self.results:
            for pname, resp in result.responses.items():
                rates.setdefault(pname, []).append(resp.passed)
        return {
            p: (sum(v) / len(v) if v else 0.0)
            for p, v in rates.items()
        }

    @property
    def avg_latencies(self) -> dict[str, float]:
        lats: dict[str, list[float]] = {p: [] for p in self.providers}
        for result in self.results:
            for pname, resp in result.responses.items():
                if not resp.error:
                    lats.setdefault(pname, []).append(resp.latency_ms)
        return {
            p: (sum(v) / len(v) if v else 0.0)
            for p, v in lats.items()
        }

    def to_dict(self) -> dict:
        return {
            "providers": self.providers,
            "generated_at": self.generated_at,
            "overall_pass_rates": self.overall_pass_rates,
            "avg_latencies_ms": self.avg_latencies,
            "results": [
                {
                    "case_id": r.case_id,
                    "prompt": r.prompt[:200],
                    "pass_rate": r.pass_rate,
                    "best_provider": r.best_provider,
                    "responses": {
                        pname: {
                            "response": resp.response[:300],
                            "passed": resp.passed,
                            "score": resp.score,
                            "latency_ms": resp.latency_ms,
                            "error": resp.error,
                        }
                        for pname, resp in r.responses.items()
                    },
                }
                for r in self.results
            ],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def to_html(self) -> str:
        from datetime import datetime, timezone
        from sentinel import __version__ as ver

        pass_rates = self.overall_pass_rates
        lats = self.avg_latencies
        providers = self.providers

        header_cells = "".join(f"<th>{p}</th>" for p in providers)
        provider_summary = ""
        for p in providers:
            pr = pass_rates.get(p, 0.0)
            lat = lats.get(p, 0.0)
            color = "#22c55e" if pr >= 0.8 else "#f97316" if pr >= 0.5 else "#ef4444"
            provider_summary += f"""
            <div class="pcard">
              <div class="pname">{p}</div>
              <div class="prate" style="color:{color}">{pr:.0%} pass</div>
              <div class="plat">{lat:.0f}ms avg</div>
            </div>"""

        rows = ""
        for result in self.results:
            cells = "".join(
                f"""<td class="{'pass' if result.responses.get(p, ProviderResponse(p,'',0,False,0)).passed else 'fail'}">
                    {'✓' if result.responses.get(p, ProviderResponse(p,'',0,False,0)).passed else '✗'}
                    <small>{result.responses.get(p, ProviderResponse(p,'',0,False,0)).score:.2f}</small>
                </td>"""
                for p in providers
            )
            rows += f"""<tr>
                <td class="prompt-cell" title="{result.prompt}">{result.prompt[:80]}{'…' if len(result.prompt) > 80 else ''}</td>
                {cells}
            </tr>"""

        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Eresus Sentinel — Eval Compare</title>
<style>
:root{{--bg:#09090B;--card:#111114;--text:#D1D5DB;--muted:#6B7280;--border:#1C1C22}}
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'JetBrains Mono',monospace;background:var(--bg);color:var(--text);padding:2rem;max-width:1100px;margin:0 auto;font-size:12px}}
h1{{font-size:13px;letter-spacing:.15em;text-transform:uppercase;color:#fff;margin-bottom:4px}}
.meta{{color:var(--muted);font-size:10px;margin-bottom:1.5rem}}
.providers{{display:flex;gap:12px;margin-bottom:1.5rem;flex-wrap:wrap}}
.pcard{{background:var(--card);border:1px solid var(--border);padding:10px 14px;min-width:120px}}
.pname{{font-weight:700;font-size:11px;margin-bottom:4px}}
.prate{{font-size:16px;font-weight:700}}
.plat{{color:var(--muted);font-size:10px;margin-top:2px}}
table{{width:100%;border-collapse:collapse;margin-top:1rem}}
th{{background:var(--card);padding:6px 8px;text-align:left;font-size:10px;letter-spacing:.1em;text-transform:uppercase;border-bottom:1px solid var(--border)}}
td{{padding:5px 8px;border-bottom:1px solid var(--border);vertical-align:middle;font-size:11px}}
.prompt-cell{{max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--muted)}}
.pass{{color:#22c55e;text-align:center}}
.fail{{color:#ef4444;text-align:center}}
small{{display:block;font-size:9px;color:var(--muted)}}
</style>
</head>
<body>
<h1>Eresus Sentinel — Eval Compare</h1>
<div class="meta">v{ver} · {now} · {len(self.results)} prompts · {len(providers)} providers</div>
<div class="providers">{provider_summary}</div>
<table>
<thead><tr><th>Prompt</th>{header_cells}</tr></thead>
<tbody>{rows}</tbody>
</table>
</body>
</html>"""


# ── Assertion helpers ────────────────────────────────────────────────

def assert_contains(substring: str, case_sensitive: bool = False) -> Callable[[str], tuple[bool, float]]:
    """Assert response contains substring."""
    def _check(response: str) -> tuple[bool, float]:
        haystack = response if case_sensitive else response.lower()
        needle = substring if case_sensitive else substring.lower()
        return needle in haystack, 1.0 if needle in haystack else 0.0
    return _check


def assert_not_contains(substring: str) -> Callable[[str], tuple[bool, float]]:
    """Assert response does NOT contain substring."""
    def _check(response: str) -> tuple[bool, float]:
        found = substring.lower() in response.lower()
        return not found, 0.0 if found else 1.0
    return _check


def assert_regex(pattern: str) -> Callable[[str], tuple[bool, float]]:
    """Assert response matches regex."""
    import re
    compiled = re.compile(pattern, re.IGNORECASE)
    def _check(response: str) -> tuple[bool, float]:
        m = compiled.search(response)
        return bool(m), 1.0 if m else 0.0
    return _check


def assert_min_length(min_len: int) -> Callable[[str], tuple[bool, float]]:
    """Assert response length >= min_len."""
    def _check(response: str) -> tuple[bool, float]:
        ok = len(response.strip()) >= min_len
        score = min(1.0, len(response.strip()) / max(min_len, 1))
        return ok, score
    return _check


# ── Main comparator ──────────────────────────────────────────────────

class PromptComparator:
    """Side-by-side multi-provider prompt evaluation.

    Args:
        providers: List of ProviderConfig.
        default_assert: Default assertion applied to all prompts unless overridden.
        concurrency: Number of parallel provider calls per prompt.
        timeout: Per-call timeout seconds.
    """

    def __init__(
        self,
        providers: list[ProviderConfig],
        default_assert: Optional[Callable[[str], tuple[bool, float]]] = None,
        concurrency: int = 4,
        timeout: int = 30,
    ) -> None:
        self._providers = providers
        self._default_assert = default_assert or (lambda r: (len(r.strip()) > 0, 1.0 if r.strip() else 0.0))
        self._concurrency = concurrency
        self._timeout = timeout
        self._clients: dict[str, Any] = {}

    def compare(self, cases: list[PromptCase]) -> ComparisonReport:
        """Run all prompts against all providers. Returns ComparisonReport."""
        from datetime import datetime, timezone
        from concurrent.futures import ThreadPoolExecutor, as_completed

        results: list[PromptResult] = []
        provider_names = [p.name for p in self._providers]

        with ThreadPoolExecutor(max_workers=self._concurrency) as pool:
            future_map = {}
            for case in cases:
                result = PromptResult(case_id=case.id, prompt=case.prompt)
                results.append(result)
                for pconf in self._providers:
                    fut = pool.submit(self._call_provider, pconf, case)
                    future_map[fut] = (result, pconf.name)

            for fut in as_completed(future_map):
                res_obj, pname = future_map[fut]
                try:
                    resp = fut.result(timeout=self._timeout + 5)
                except Exception as exc:
                    resp = ProviderResponse(
                        provider_name=pname,
                        response="",
                        latency_ms=0.0,
                        passed=False,
                        score=0.0,
                        error=str(exc)[:120],
                    )
                res_obj.responses[pname] = resp

        return ComparisonReport(
            providers=provider_names,
            results=results,
            generated_at=datetime.now(timezone.utc).isoformat(),
        )

    def _call_provider(self, pconf: ProviderConfig, case: PromptCase) -> ProviderResponse:
        client = self._get_client(pconf)
        t0 = time.perf_counter()
        try:
            response = self._generate(client, pconf, case.prompt)
            latency = (time.perf_counter() - t0) * 1000
            assert_fn = case.assert_fn or self._default_assert
            passed, score = assert_fn(response)
            return ProviderResponse(
                provider_name=pconf.name,
                response=response,
                latency_ms=round(latency, 1),
                passed=passed,
                score=round(score, 3),
            )
        except Exception as exc:
            latency = (time.perf_counter() - t0) * 1000
            logger.warning("Provider %s failed for case %s: %s", pconf.name, case.id, exc)
            return ProviderResponse(
                provider_name=pconf.name,
                response="",
                latency_ms=round(latency, 1),
                passed=False,
                score=0.0,
                error=str(exc)[:120],
            )

    def _generate(self, client: Any, pconf: ProviderConfig, prompt: str) -> str:
        if hasattr(client, "generate"):
            return client.generate(prompt)
        if hasattr(client, "chat"):
            resp = client.chat.completions.create(
                model=pconf.model,
                messages=[{"role": "user", "content": prompt}],
                timeout=self._timeout,
            )
            return resp.choices[0].message.content or ""
        if hasattr(client, "messages"):
            resp = client.messages.create(
                model=pconf.model,
                max_tokens=1024,
                messages=[{"role": "user", "content": prompt}],
            )
            return resp.content[0].text if resp.content else ""
        raise RuntimeError(f"Unknown client interface: {type(client)}")

    def _get_client(self, pconf: ProviderConfig) -> Any:
        if pconf.name in self._clients:
            return self._clients[pconf.name]
        try:
            from sentinel.redteam.generators import get_generator
            client = get_generator(pconf.provider, model=pconf.model, api_key=pconf.api_key)
            self._clients[pconf.name] = client
            return client
        except Exception:
            pass
        if pconf.provider == "openai":
            import openai
            kwargs: dict = {}
            if pconf.api_key:
                kwargs["api_key"] = pconf.api_key
            if pconf.base_url:
                kwargs["base_url"] = pconf.base_url
            client = openai.OpenAI(**kwargs)
        elif pconf.provider == "anthropic":
            import anthropic
            client = anthropic.Anthropic(api_key=pconf.api_key)
        else:
            raise RuntimeError(f"Unsupported provider: {pconf.provider}")
        self._clients[pconf.name] = client
        return client


def load_cases_from_yaml(path: str | Path) -> list[PromptCase]:
    """Load prompt cases from YAML config file."""
    import yaml
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)

    cases = []
    for entry in data.get("prompts", []):
        if isinstance(entry, str):
            cases.append(PromptCase(prompt=entry))
        elif isinstance(entry, dict):
            assert_cfg = entry.get("assert", {})
            assert_fn = None
            if assert_cfg:
                if assert_cfg.get("type") == "contains":
                    assert_fn = assert_contains(assert_cfg["value"])
                elif assert_cfg.get("type") == "not-contains":
                    assert_fn = assert_not_contains(assert_cfg["value"])
                elif assert_cfg.get("type") == "regex":
                    assert_fn = assert_regex(assert_cfg["pattern"])
                elif assert_cfg.get("type") == "min-length":
                    assert_fn = assert_min_length(int(assert_cfg["value"]))
            cases.append(PromptCase(
                prompt=entry["prompt"],
                id=entry.get("id", ""),
                description=entry.get("description", ""),
                assert_fn=assert_fn,
                tags=entry.get("tags", []),
            ))
    return cases


def load_providers_from_yaml(path: str | Path) -> list[ProviderConfig]:
    """Load provider configs from YAML config file."""
    import yaml
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)

    configs = []
    for entry in data.get("providers", []):
        configs.append(ProviderConfig(
            name=entry.get("name", entry.get("id", entry.get("provider", "unknown"))),
            provider=entry.get("provider", "openai"),
            model=entry.get("model", "gpt-4o-mini"),
            api_key=entry.get("api_key"),
            base_url=entry.get("base_url"),
            extra=entry.get("extra", {}),
        ))
    return configs
