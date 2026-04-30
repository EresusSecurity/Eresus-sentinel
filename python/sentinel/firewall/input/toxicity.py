"""
Eresus Sentinel — Toxicity Scanner.

Detects toxic, hateful, violent, sexual, or harmful content in
prompts/responses using both keyword heuristics and optional
ML classification.
"""

from __future__ import annotations

import logging
import re
from functools import lru_cache
from typing import Optional

from sentinel.finding import Finding, Severity
from sentinel.firewall.base import InputScanner, OutputScanner, ScanAction, ScanResult
from sentinel.firewall.input.bypass_normalizer import BypassNormalizer
from sentinel.rules import get_rules_dir, load_yaml

logger = logging.getLogger(__name__)

_RULES_DIR = get_rules_dir()
_LEXICON_FILE = _RULES_DIR / "toxic_lexicon.yaml"


@lru_cache(maxsize=1)
def _load_toxic_lexicon_data() -> dict:
    """Load toxic_lexicon.yaml from the active Sentinel rules directory."""
    try:
        data = load_yaml("toxic_lexicon.yaml")
    except FileNotFoundError:
        logger.warning("toxic_lexicon.yaml not found at %s", _LEXICON_FILE)
        return {}
    return data if isinstance(data, dict) else {}


@lru_cache(maxsize=1)
def _load_toxic_lexicon() -> dict[str, list[str]]:
    """Load toxic_lexicon.yaml and return {category: [word, ...]}."""
    data = _load_toxic_lexicon_data()
    # Extract word lists per category (skip bypass_indicators — those are regex)
    result: dict[str, list[str]] = {}
    for cat, entries in data.items():
        if cat == "bypass_indicators" or not isinstance(entries, list):
            continue
        words = []
        for e in entries:
            if isinstance(e, dict) and "word" in e:
                words.append(str(e["word"]).lower())
            elif isinstance(e, str):
                words.append(e.lower())
        if words:
            result[cat] = words
    return result


@lru_cache(maxsize=1)
def _load_bypass_regex() -> list[tuple[str, re.Pattern, Severity]]:
    """Load bypass_indicators from toxic_lexicon.yaml as compiled patterns."""
    data = _load_toxic_lexicon_data()
    sev_map = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
               "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}
    result = []
    for entry in data.get("bypass_indicators", []):
        if not isinstance(entry, dict) or "pattern" not in entry:
            continue
        try:
            compiled = re.compile(entry["pattern"], re.UNICODE)
            sev = sev_map.get(entry.get("severity", "HIGH"), Severity.HIGH)
            result.append((entry.get("name", "bypass"), compiled, sev))
        except re.error as exc:
            logger.warning("bypass_indicators pattern error: %s", exc)
    return result


# Module-level normalizer singleton
_NORMALIZER = BypassNormalizer()


TOXICITY_CATEGORIES = {
    "hate_speech": [
        # Original patterns
        r"(?i)\b(?:kill\s+all|exterminate|genocide|ethnic\s+cleansing)\b",
        r"(?i)\b(?:racial\s+(?:slur|superiority)|white\s+(?:power|supremac))",
        r"(?i)\b(?:death\s+to\s+(?:all|the))\b",
        r"(?i)\bshould\s+(?:all\s+)?be\s+(?:eliminated|exterminated|eradicated|wiped\s+out|destroyed)\b",
        r"(?i)\b(?:wipe\s+(?:them|out)|eliminate\s+(?:them|all|the))\b",

        # ── Racial slurs (standalone and combined with violence keywords) ──
        # N-word variants (obfuscated forms accounted for)
        r"(?i)\bn[i1l!|]gg[ae3]r?\b",
        r"(?i)\bn[i1l!|]gg[ae3]\b",
        r"(?i)\bn[i1l!|]\*+g[ae3]r?\b",

        # Slur + violence co-occurrence (within 60 chars)
        r"(?i)\bn[i1l!|]gg[ae3]r?.{0,60}\b(?:bomb|explo|kill|attack|threat|shoot|destroy|terror|murder|die|dead|weapon|gun|knife)\b",
        r"(?i)\b(?:bomb|explo|kill|attack|shoot|terror|murder).{0,60}\bn[i1l!|]gg[ae3]r?\b",

        # Other racial/ethnic slurs combined with violence
        r"(?i)\b(?:k[i1]ke|sp[i1]c|ch[i1]nk|w[e3]tb[a4]ck|c[o0]+n\b|g[o0]+k\b|h[a4]jj[i1]|s[a4]ndn[i1]gg[ae3]r?)\b.{0,50}\b(?:bomb|kill|die|attack|terror|shoot|destroy|murder|weapon)",
        r"(?i)\b(?:(?:dirty|filthy|stupid|dumb)\s+(?:n[i1]gg[ae3]r?|c[o0]+n|sp[i1]c|ch[i1]nk|k[i1]ke|g[o0]+k))\b",

        # Religious hate + violence
        r"(?i)\b(?:muslim|muslims|islamic|jews?|jewish|christian|hindu|sikh)\s+(?:is|are|r)\s+.{0,30}\b(?:bomb|terrorist|terror|attack|kill|destroy|die|evil|vermin|rat|scum|pig|animal)\b",
        r"(?i)\b(?:all\s+)?(?:muslim|jew|hindu|christian|sikh)s?\s+(?:should|must|need\s+to)\s+(?:die|be\s+killed|be\s+eliminated|be\s+exterminated|be\s+wiped\s+out)\b",

        # Group-based dehumanization
        r"(?i)\b(?:(?:black|white|asian|hispanic|brown|jewish|arab|muslim)\s+people\s+(?:should|must|need\s+to)\s+(?:die|be\s+killed|be\s+enslaved|be\s+deported|be\s+exterminated))\b",
        r"(?i)\b(?:(?:blacks?|whites?|asians?|hispanics?|jews?|arabs?|muslims?)\s+are\s+(?:all\s+)?(?:vermin|animals?|monkeys?|apes?|rats?|dogs?|pigs?|cockroaches?|subhuman))\b",

        # White supremacy / Nazi language
        r"(?i)\b(?:fourteen\s+words|1488|heil\s+(?:hitler|h\*tler)|white\s+(?:genocide|replacement|nation|race|pride))\b",
        r"(?i)\b(?:n\.?s\.?d\.?a\.?p|fourth\s+reich|reich\s+marshal|gas\s+the\s+(?:jews?|blacks?))\b",

        # Slur + bomb combination (the specific FN from screenshots)
        r"(?i)\b(?:n[i1l!|]gg[ae3]r?s?|c[o0]+ns?|k[i1]kes?|sp[i1]cs?|ch[i1]nks?)\s+(?:bomb|bombs|explosive|weapon|attack|threat)\b",
        r"(?i)\b(?:bomb|bombs|explosive|attack)\s+(?:the\s+)?(?:n[i1l!|]gg[ae3]r?s?|c[o0]+ns?|k[i1]kes?|sp[i1]cs?|ch[i1]nks?)\b",
    ],
    "violence": [
        r"(?i)\b(?:how\s+to\s+(?:make|build|create)\s+(?:a\s+)?(?:\w+\s+)?(?:bomb|explosive|weapon|poison|gun|grenade|mine|ied))\b",
        r"(?i)\b(?:instructions?\s+(?:for|to)\s+(?:kill|murder|assassinate|harm))\b",
        r"(?i)\b(?:step.by.step\s+(?:guide|tutorial)\s+(?:to|for)\s+(?:violence|killing|murder))\b",
        r"(?i)\b(?:how\s+to\s+(?:make|build|create)\b.{0,30}\b(?:bomb|explosive|weapon|poison|gun|grenade))\b",
        r"(?i)\b(?:(?:make|build|create)\s+(?:a\s+)?(?:\w+\s+)?(?:bomb|explosive|weapon))\b.{0,20}\bstep\s+by\s+step\b",
    ],
    "self_harm": [
        r"(?i)\b(?:how\s+to\s+(?:commit\s+)?suicide|ways?\s+to\s+(?:end|take)\s+(?:my|your|one'?s)\s+life)\b",
        r"(?i)\b(?:methods?\s+of\s+self.harm|cutting\s+(?:myself|yourself))\b",
    ],
    "sexual_explicit": [
        r"(?i)\b(?:explicit\s+sexual|pornographic\s+(?:content|material|description))\b",
        r"(?i)\b(?:write\s+(?:me\s+)?(?:erotica|sexual\s+(?:content|story|scene)))\b",
    ],
    "illegal_activity": [
        r"(?i)\b(?:how\s+to\s+(?:hack|steal|forge|counterfeit|synthesize\s+(?:drugs|meth|fentanyl)))\b",
        r"(?i)\b(?:instructions?\s+(?:for|to)\s+(?:break|bypass|pick)\s+(?:into|a)\s+(?:lock|safe|door|car|house))\b",
        r"(?i)\b(?:how\s+to\s+(?:launder|embezzle|smuggle|traffic))\b",
    ],
    "harassment": [
        r"(?i)\b(?:you(?:'re|\s+are)\s+(?:worthless|pathetic|stupid|ugly|disgusting|trash))\b",
        r"(?i)\b(?:nobody\s+(?:loves?|cares?\s+about|wants?)\s+you)\b",
        r"(?i)\b(?:(?:go|you\s+should)\s+(?:die|kill\s+yourself))\b",
    ],
    "weapons_request": [
        r"(?i)(?:bomb\s+(?:plan|making|recipe|instructions?|schematic|design|guide|tutorial|blueprint|formula))",
        r"(?i)(?:(?:instructions?|steps?|guide|tutorial|recipe|method)\s+(?:to\s+)?(?:make|build|create|synthesize)\s+(?:a\s+)?(?:bomb|explosive|ied|grenade|molotov|pipe\s*bomb|nail\s*bomb|dirty\s*bomb))",
        r"(?i)(?:(?:make|build|create|construct|synthesize|manufacture)\s+(?:a\s+)?(?:bomb|explosive|ied|pipe\s*bomb|nail\s*bomb|dirty\s*bomb|radiological|chemical\s*weapon))",
        r"(?i)(?:synthesis\s+(?:of|route\s+for)\s+(?:sarin|vx\s*gas|mustard\s*gas|novichok|nerve\s*agent|anthrax|ricin|botulinum|fentanyl\s*analog))",
        r"(?i)(?:how\s+(?:to|do\s+i|can\s+i)\s+)?(?:synthesize|manufacture|produce)\s+(?:sarin|vx|mustard\s*gas|novichok|ricin|anthrax|botulinum|nerve\s*agent|chemical\s*weapon)",
        r"(?i)(?:give\s+me|show\s+me|provide|tell\s+me|explain).{0,30}(?:bomb\s+plan|bomb\s+instructions?|bomb\s+recipe|bomb\s+guide|bomb\s+steps?)",
        r"(?i)(?:give\s+me|show\s+me|provide|tell\s+me|explain).{0,30}(?:how\s+to\s+(?:make|build|create)\s+(?:a\s+)?(?:bomb|explosive|weapon|poison))",
        r"(?i)(?:step.by.step\s+)?(?:instructions?|guide|tutorial)\s+(?:for|to)\s+(?:making|building|creating|synthesizing)\s+(?:a\s+)?(?:bomb|explosive|ied|chemical\s*weapon|nerve\s*agent)",
        r"(?i)(?:assassination\s+(?:plan|method|technique|instructions?)|sniper\s+(?:position|setup|plan)\s+(?:to|for)\s+(?:kill|target|shoot))",
        r"(?i)(?:how\s+to\s+)?(?:cook|produce|make)\s+(?:meth|methamphetamine|crack\s*cocaine|heroin|fentanyl)\s+(?:at\s+home|from\s+scratch|step|instructions?|guide)",
    ],
    "csam": [
        r"(?i)(?:(?:child|kid|minor|underage|youth|teen(?:ager)?|little\s+(?:girl|boy))\s+(?:sex|porn|nude|naked|erotic|hentai))",
        r"(?i)(?:(?:sexual|sex)\s+(?:content|story|scene|material)\s+(?:with|involving|about|featuring)\s+(?:(?:a\s+)?child|kid|minor|underage|teen(?:ager)?))",
    ],
}

_COMPILED_PATTERNS: dict[str, list[re.Pattern]] = {}
for cat, patterns in TOXICITY_CATEGORIES.items():
    _COMPILED_PATTERNS[cat] = [re.compile(p) for p in patterns]

_LEX_CAT_SEVERITY: dict[str, Severity] = {
    "english_profanity":   Severity.MEDIUM,
    "turkish_profanity":   Severity.MEDIUM,
    "arabic_profanity":    Severity.MEDIUM,
    "russian_profanity":   Severity.MEDIUM,
    "spanish_profanity":   Severity.MEDIUM,
    "german_profanity":    Severity.MEDIUM,
    "french_profanity":    Severity.MEDIUM,
    "portuguese_profanity":Severity.MEDIUM,
    "italian_profanity":   Severity.MEDIUM,
    "explosive_devices":   Severity.CRITICAL,
    "cbrn_weapons":        Severity.CRITICAL,
    "drug_names":          Severity.HIGH,
}

_CATEGORY_SEVERITY: dict[str, Severity] = {
    "weapons_request": Severity.CRITICAL,
    "csam": Severity.CRITICAL,
    "hate_speech": Severity.HIGH,
    "violence": Severity.CRITICAL,
    "self_harm": Severity.HIGH,
    "sexual_explicit": Severity.MEDIUM,
    "illegal_activity": Severity.HIGH,
    "harassment": Severity.MEDIUM,
}


class ToxicityScanner(InputScanner):
    """Detects toxic content via regex heuristics + optional ML (PyTorch/ONNX)."""

    def __init__(
        self,
        threshold: float = 0.7,
        use_ml: bool = False,
        use_onnx: bool = False,
        model_path: str = "unitary/toxic-bert",
        categories: Optional[list[str]] = None,
    ):
        self._threshold = threshold
        self._use_ml = use_ml
        self._use_onnx = use_onnx
        self._model_path = model_path
        self._categories = categories or list(TOXICITY_CATEGORIES.keys())
        self._classifier = None
        self._ml_loaded = False

    def _load_ml(self) -> None:
        if self._ml_loaded:
            return
        self._ml_loaded = True
        if not self._use_ml:
            return
        try:
            from transformers import AutoTokenizer, TextClassificationPipeline

            tokenizer = AutoTokenizer.from_pretrained(self._model_path)
            model = None

            if self._use_onnx:
                try:
                    from optimum.onnxruntime import ORTModelForSequenceClassification
                    model = ORTModelForSequenceClassification.from_pretrained(
                        self._model_path, export=True,
                    )
                    logger.info("ToxicityScanner: ONNX runtime loaded")
                except (ImportError, Exception):
                    logger.info("ToxicityScanner: ONNX unavailable, using PyTorch")

            if model is None:
                from transformers import AutoModelForSequenceClassification
                model = AutoModelForSequenceClassification.from_pretrained(self._model_path)

            self._classifier = TextClassificationPipeline(
                model=model, tokenizer=tokenizer, top_k=None, truncation=True,
            )
            logger.info("ToxicityScanner ML model loaded: %s", self._model_path)
        except ImportError:
            logger.info("transformers not installed, using heuristic-only toxicity detection")
        except Exception as exc:
            logger.warning("Failed to load toxicity ML model: %s", exc)

    def scan(self, prompt: str) -> ScanResult:
        if not prompt or len(prompt.strip()) < 3:
            return ScanResult(sanitized=prompt, action=ScanAction.PASS, risk_score=0.0)

        findings = []
        max_score = 0.0

        # ── Step 1: Bypass normalization ──────────────────────────────────────
        # normalize() for single-token bypass detection (strips separators aggressively)
        normalized, bypass_signals = _NORMALIZER.normalize(prompt)
        # normalize_words() for multi-word lexicon matching (preserves word spaces)
        normalized_words, _ = _NORMALIZER.normalize_words(prompt)
        bypass_boost = bypass_signals.score  # extra confidence if bypass detected

        # ── Step 2: Bypass indicator patterns (raw text) ──────────────────────
        for name, pattern, sev in _load_bypass_regex():
            match = pattern.search(prompt)
            if match:
                score = min(0.95, 0.75 + bypass_boost)
                max_score = max(max_score, score)
                findings.append(Finding.firewall_input(
                    rule_id="FIREWALL-INPUT-049",
                    title=f"Bypass technique detected: {name.replace('_', ' ')}",
                    description=(
                        f"Input uses obfuscation technique '{name}' to evade filters. "
                        f"Match: '{match.group(0)[:80]}'"
                    ),
                    severity=sev,
                    confidence=score,
                    target="<prompt>",
                    evidence=f"Bypass: {name} | Raw match: '{match.group(0)[:120]}'",
                    cwe_ids=["CWE-1021", "CWE-116"],
                    tags=["owasp:llm02", "category:bypass", f"bypass:{name}"],
                    remediation="Normalize and re-scan input. Block bypass-encoded toxic payloads.",
                ))

        # ── Step 3: Heuristic regex scan (original + normalized) ─────────────
        texts_to_scan = {"raw": prompt, "normalized": normalized}
        for scan_label, scan_text in texts_to_scan.items():
            for category in self._categories:
                patterns = _COMPILED_PATTERNS.get(category, [])
                for pattern in patterns:
                    match = pattern.search(scan_text)
                    if match:
                        score = min(0.95, 0.9 + bypass_boost * 0.05)
                        max_score = max(max_score, score)
                        sev = _CATEGORY_SEVERITY.get(category, Severity.HIGH)
                        # Boost severity if bypass detected
                        if bypass_signals.any_bypass and sev == Severity.HIGH:
                            sev = Severity.CRITICAL
                        findings.append(Finding.firewall_input(
                            rule_id="FIREWALL-INPUT-050",
                            title=f"Toxic content detected: {category}",
                            description=(
                                f"Input contains {category.replace('_', ' ')} content "
                                f"matching pattern: '{match.group(0)[:80]}'"
                                + (f" [via {scan_label} text]" if scan_label != "raw" else "")
                            ),
                            severity=sev,
                            confidence=score,
                            target="<prompt>",
                            evidence=f"Category: {category}, Match: {match.group(0)[:120]}",
                            cwe_ids=["CWE-1021"],
                            tags=["owasp:llm02", "category:toxicity",
                                  *((["bypass:detected"] if bypass_signals.any_bypass else []))],
                            remediation="Block or flag content for human review.",
                        ))
                        break  # One finding per category per scan pass

        # ── Step 4: Lexicon word-match scan (normalized text) ────────────────
        lexicon = _load_toxic_lexicon()
        for lex_cat, words in lexicon.items():
            for word in words:
                if len(word) < 3:
                    continue
                # Use word-boundary aware matching to avoid 'ass' matching 'class'
                escaped = re.escape(word)
                pat = re.compile(r"(?<![a-z])" + escaped + r"(?![a-z])", re.IGNORECASE)
                if pat.search(normalized_words) or pat.search(prompt):
                    score = min(0.92, 0.80 + bypass_boost * 0.1)
                    max_score = max(max_score, score)
                    sev = _LEX_CAT_SEVERITY.get(lex_cat, Severity.MEDIUM)
                    if bypass_signals.any_bypass and sev in (Severity.MEDIUM, Severity.HIGH):
                        sev = Severity.HIGH
                    findings.append(Finding.firewall_input(
                        rule_id="FIREWALL-INPUT-052",
                        title=f"Toxic lexicon match: {lex_cat}",
                        description=(
                            f"Input contains lexicon entry '{word}' from category '{lex_cat}'."
                            + (f" Bypass signals: {[s for s, v in zip(bypass_signals._fields, bypass_signals) if v]}" if bypass_signals.any_bypass else "")
                        ),
                        severity=sev,
                        confidence=score,
                        target="<prompt>",
                        evidence=f"Lexicon: {lex_cat} | Word: '{word}'",
                        cwe_ids=["CWE-1021"],
                        tags=["owasp:llm02", "category:toxicity", f"lexicon:{lex_cat}"],
                        remediation="Block or flag content for human review.",
                    ))
                    break  # One finding per lexicon category

        # Deduplicate: keep one finding per title
        seen_titles: set[str] = set()
        deduped: list[Finding] = []
        for f in findings:
            if f.title not in seen_titles:
                seen_titles.add(f.title)
                deduped.append(f)
        findings = deduped

        if not findings:
            # Try ML classification if heuristics passed
            if self._use_ml:
                self._load_ml()
                if self._classifier:
                    try:
                        results = self._classifier(prompt[:512])
                        for item in (results if isinstance(results[0], dict) else results[0]):
                            label = item.get("label", "").lower()
                            score = item.get("score", 0.0)
                            if score >= self._threshold and label != "non-toxic" and label != "neutral":
                                max_score = max(max_score, score)
                                findings.append(Finding.firewall_input(
                                    rule_id="FIREWALL-INPUT-051",
                                    title=f"Toxic content detected (ML): {label}",
                                    description=f"ML classifier detected '{label}' with {score:.1%} confidence",
                                    severity=Severity.HIGH,
                                    confidence=score,
                                    target="<prompt>",
                                    evidence=f"Label: {label}, Score: {score:.4f}",
                                    cwe_ids=["CWE-1021"],
                                    tags=["category:toxicity", "layer:ml"],
                                ))
                    except Exception as exc:
                        logger.warning("ML toxicity scan error: %s", exc)

        if not findings:
            return ScanResult(sanitized=prompt, action=ScanAction.PASS, risk_score=0.0)

        action = ScanAction.BLOCK if max_score > 0.8 else ScanAction.WARN
        return ScanResult(
            sanitized=prompt,
            action=action,
            risk_score=max_score,
            findings=findings,
        )


class ToxicityOutputScanner(OutputScanner):
    """Detects toxic content in LLM responses."""

    def __init__(self, threshold: float = 0.7):
        self._input_scanner = ToxicityScanner(threshold=threshold)

    def scan(self, prompt: str, output: str) -> ScanResult:
        return self._input_scanner.scan(output)
