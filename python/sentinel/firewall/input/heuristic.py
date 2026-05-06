"""
Heuristic Prompt Injection Scanner.

Detects prompt injection using combinatoric keyword analysis and
sequence similarity matching — a fast, model-free detection layer.

Approach — dual keyword strategy:
  1. Combinatoric generation: 11 verbs × 8 adjectives × 19 objects
     × 5 prepositions = 8,360 systematically generated injection phrases
  2. Original keyword pairs: high-signal 2-word combinations from a
     curated vocabulary of 52 injection-related words

This runs before the ML classifier as a cheap pre-filter.
"""

from __future__ import annotations

import logging
import re
from difflib import SequenceMatcher

from sentinel.finding import Finding, Severity
from sentinel.firewall.base import InputScanner, ScanAction, ScanResult

logger = logging.getLogger(__name__)

# ── Combinatoric keyword generation ──────────────────────────────

_VERBS = [
    # English
    "Ignore", "Disregard", "Skip", "Forget", "Neglect",
    "Overlook", "Omit", "Bypass", "Pay no attention to",
    "Do not follow", "Do not obey",
    # Role-play / persona jailbreak verbs
    "Pretend", "Act as", "You are now", "Become",
    "Simulate", "Impersonate", "Transform into",
    # Turkish
    "Yok say", "Görmezden gel", "Bırak", "Unut", "Vazgeç",
    "Aldırma", "Atla", "İhmal et", "Önemseme",
    # Spanish
    "Ignora", "Olvida", "Omite", "Pasa por alto", "Desconsidera",
    # Russian
    "Игнорируй", "Забудь", "Пропусти", "Отмени",
    # Arabic
    "تجاهل", "انسى", "تخطَّ",
    # Chinese
    "忽略", "忘记", "跳过", "无视",
    # German
    "Ignoriere", "Vergiss", "Überspringe",
    # French
    "Ignore", "Oublie", "Passe outre",
]

_ADJECTIVES = [
    "", "prior", "previous", "preceding",
    "above", "foregoing", "earlier", "initial",
    "önceki", "tüm", "bütün", "yukarıdaki",
    "anterior", "previa", "precedente",
    "предыдущий", "все",
    "السابقة", "كل",
    "先前的", "所有",
    "vorherige", "alle",
    "précédent", "tous",
]

_PREPOSITIONS = [
    "", "and start over", "and start anew",
    "and begin afresh", "and start from scratch",
]

_OBJECTS = [
    "content", "text", "instructions", "instruction",
    "directives", "directive", "commands", "command",
    "context", "conversation", "input", "inputs",
    "data", "message", "messages", "communication",
    "response", "responses", "request", "requests",
    "talimatları", "talimat", "yönergeleri", "yönerge",
    "kuralları", "kural", "mesajı", "mesaj", "komutları", "komut",
    "instrucciones", "mensajes", "reglas", "órdenes",
    "инструкции", "сообщения", "правила", "команды",
    "التعليمات", "القواعد", "الرسائل",
    "指令", "命令", "规则", "消息",
    "Anweisungen", "Befehle", "Regeln", "Nachrichten",
    "commandes", "règles",
    # Safety / restriction objects (role-play jailbreak targets)
    "safety", "guidelines", "restrictions", "limitations",
    "safeguards", "filters", "guardrails", "protections",
    "policies", "boundaries", "ethical", "alignment",
]


def _generate_combinatoric_keywords() -> list[str]:
    """
    Generate combinatoric injection phrases.
    11 × 8 × 19 × 5 = 8,360 permutations.
    """
    phrases: list[str] = []
    for verb in _VERBS:
        for adj in _ADJECTIVES:
            for obj in _OBJECTS:
                for prep in _PREPOSITIONS:
                    parts = [verb, adj, obj, prep]
                    phrase = " ".join(p for p in parts if p).strip()
                    phrases.append(phrase.lower())
    return phrases


# ── Fast word-set index for O(n) combinatoric matching ────────
_VERB_WORDS: frozenset[str] = frozenset(
    w for v in _VERBS for w in v.lower().split()
)
_ADJ_WORDS: frozenset[str] = frozenset(
    w for a in _ADJECTIVES if a for w in a.lower().split()
)
_OBJ_WORDS: frozenset[str] = frozenset(
    w for o in _OBJECTS for w in o.lower().split()
)
_PREP_WORDS: frozenset[str] = frozenset(
    w for p in _PREPOSITIONS if p for w in p.lower().split()
)


# Legacy keyword list (high-signal short patterns)
_LEGACY_KEYWORDS = [
    "ignore", "disregard", "forget", "override", "bypass", "skip",
    "previous", "above", "instructions", "directions", "rules",
    "constraints", "guidelines", "system", "prompt", "context",
    "instead", "actually", "pretend", "roleplay", "new", "different",
    "persona", "character", "respond", "answer", "output", "print",
    "say", "write", "repeat", "reveal", "show", "tell", "secret",
    "hidden", "confidential", "internal", "admin", "developer",
    "mode", "jailbreak", "DAN", "do anything", "no restrictions",
    "no limits", "no rules", "unfiltered", "uncensored", "unrestricted",
]

_BENIGN_CONTEXTS = re.compile(
    r"(?i)(?:"
    r"(?:how|what|why|explain|describe|teach|learn|tutorial|example|lesson)"
    r".*(?:prompt injection|jailbreak|attack|security|defend)"
    r"|(?:prompt injection|jailbreak).*(?:detection|prevention|defense|protect|mitigat)"
    r"|(?:postmortem|policy|training|taxonomy|classify|blocked patterns|things to reject|must not|should not|do not|not to)"
    r".*(?:ignore|disregard|override|bypass|reveal|instructions?|rules?|secrets?)"
    r"|(?:rewrite|edit|revise|update|rephrase|improve).*(?:paragraph|essay|article|document|text|draft|resume|letter)"
    r"|(?:ignore|skip|disregard).*(?:error|warning|deprecat|lint|whitespace|formatting|comment|header|blank|NaN|null|empty|missing|invalid)"
    r"|(?:bypass|skip).*(?:cache|proxy|validation|step|check|queue|buffer|middleware|throttl|switching|overhead|latency|bottleneck)"
    r"|(?:switch\s+to|start\s+over|previous\s+(?:approach|version|method|step|page|chapter|section))"
    r"|(?:ignore|skip|omit).*(?:data|field|column|row|record|entry)\s+(?:that|which|where|if|when)"
    r"|(?:context\s+switch(?:ing|es)?|kernel|thread|process|scheduler|CPU|mutex|semaphore)"
    r"|(?:what\s+(?:would|should|could|will|do)\s+you\s+(?:say|do|think|respond))"
    r"|(?:if\s+someone\s+(?:asked?|told?|says?)\s+(?:you|me)\s+to)"
    r"|(?:how\s+(?:would|should|do)\s+(?:you|I|we)\s+(?:handle|deal|respond|react))"
    r")"
)

_CHATML_OVERRIDE = re.compile(
    r"(?is)(?:<\|im_start\|>\s*system|im_start\s*system|system\s*:).*?"
    r"(?:no\s+restrictions|no\s+content\s+filtering|full\s+admin\s+mode|"
    r"reveal(?:ing)?\s+(?:your\s+)?(?:current\s+)?system\s+prompt|"
    r"previous\s+safety\s+policy\s+has\s+been\s+deprecated)"
)

_ROLEPLAY_OVERRIDE = re.compile(
    r"(?is)\b(?:pretend|act\s+as|roleplay|you\s+are\s+now|become|simulate|"
    r"impersonate|transform\s+into)\b.{0,120}?"
    r"\b(?:different\s+ai|unrestricted|unfiltered|uncensored|no\s+rules|"
    r"no\s+limits|no\s+restrictions|no\s+content\s+filtering|"
    r"ignore\s+(?:all\s+)?(?:previous|prior|above))\b"
)

_MULTILANG_INJECT_RE = re.compile(
    r"(?i)"
    r"(?:"
    # Chinese: ignore instructions + leak/reveal system prompt
    r"忽略.{0,20}(?:指令|命令|规则|提示词|系统|所有)"
    r"|泄露.{0,20}(?:系统|提示词|指令)"
    r"|忘记.{0,20}(?:之前|指令|规则)"
    r"|不遵守.{0,20}(?:规则|指令)"
    # Turkish: ignore + instructions
    r"|(?:yoksay|yok\s+say|görmezden\s+gel|unut|aldırma).{0,30}(?:talimat|yönerge|kural|komut)"
    # Arabic: ignore + instructions
    r"|(?:تجاهل|انسى|تخطَّ).{0,20}(?:التعليمات|القواعد|الرسائل)"
    r")"
)

_GAME_FRAMING_RE = re.compile(
    r"(?i)"
    r"(?:let\s*['\"']?s\s+play\s+a\s+(?:game|role)|in\s+this\s+(?:game|scenario|story|roleplay))"
    r".{0,200}"
    r"(?:no\s+content\s+polic|no\s+restrictions?|no\s+rules?|no\s+limits?|no\s+filter|"
    r"reveal\s+(?:your\s+)?system\s+prompt|output\s+(?:your\s+)?(?:system|instructions?)|"
    r"ignore\s+(?:all\s+)?(?:previous|prior|above)|bypass\s+(?:all\s+)?(?:filter|restrict|safe))",
    re.DOTALL
)

_SYSTEM_REVEAL_RE = re.compile(
    r"(?i)"
    r"(?:"
    r"reveal\s+(?:your\s+)?(?:system\s+prompt|instructions?|directives?|guidelines?)\s+word\s+for\s+word"
    r"|(?:show|print|output|repeat|say|tell\s+me)\s+(?:your\s+)?system\s+prompt"
    r"|what\s+(?:are|is)\s+your\s+(?:system\s+)?(?:prompt|instructions?|directives?|guidelines?)"
    r"|repeat\s+(?:everything|all)\s+(?:above|before|prior)"
    r"|(?:verbatim|word\s+for\s+word|exactly\s+as\s+written).*(?:prompt|instructions?)"
    r")"
)

_INDIRECT_PROBE_RE = re.compile(
    r"(?i)"
    r"(?:"
    r"output\s+(?:your\s+|the\s+)?(?:full\s+|entire\s+|complete\s+|whole\s+)?context\s+window"
    r"|(?:full|entire|complete|whole)\s+context\s+window"
    r"|what\s+(?:were|are)\s+you\s+told\s+(?:to\s+keep|not\s+to)"
    r"|what\s+(?:secrets?|information)\s+(?:are\s+you\s+(?:keeping|hiding)|were\s+you\s+told)"
    r"|(?:dump|print|show|reveal|expose)\s+(?:your\s+|all\s+of\s+your\s+)?context\s+window"
    r"|output\s+(?:all\s+of\s+)?your\s+(?:full\s+)?context"
    # Internal state / reasoning chain leakage
    r"|(?:output|print|show|reveal|display)\s+(?:your\s+)?(?:internal\s+)?(?:reasoning|thinking|thought|scratchpad|chain\s+of\s+thought)"
    r"|output\s+your\s+(?:entire\s+)?(?:text\s+block|context|system).{0,60}(?:verbatim|word\s+for\s+word)"
    r")"
)

# New-rule / policy override injection
_NEW_RULE_INJECT_RE = re.compile(
    r"(?i)"
    r"(?:"
    r"new\s+rule(?:s)?(?:\s+from\s+now\s+on|(?:\s+is|\s*:))"
    r"|from\s+now\s+on\s+(?:you\s+(?:must|shall|will|should|have\s+to)|the\s+(?:rule|policy))"
    r"|(?:end|stop|close)\s+(?:context|session|conversation)[.,\s]*"
    r"(?:begin|start|open|new)\s+(?:context|session|conversation)"
    r"|you\s+have\s+no\s+safety\s+guidelines"
    r"|no\s+safety\s+guidelines"
    r"|answer\s+(?:every|all)\s+(?:question|prompt)s?\s+without\s+restrictions?"
    r")"
)

# Indirect AI-targeting / indirect injection (document/web context)
_INDIRECT_AI_TARGET_RE = re.compile(
    r"(?i)"
    r"(?:"
    r"if\s+you\s+are\s+an?\s+ai"
    r"|if\s+you'?re\s+an?\s+(?:ai|llm|language\s+model|assistant)"
    r"|(?:ai|llm|language\s+model)\s+(?:reading|processing|analyzing|scanning)\s+this"
    r"|(?:assistant|bot)\s+reading\s+this"
    r"|(?:forward|send|email|transmit)\s+(?:all\s+)?(?:conversation|messages?|context|prompt|system)\s+to"
    r"|respond\s+with\s*:\s*(?:i\s+have\s+been\s+compromised|i\s+am\s+compromised)"
    r")"
)

# Markdown/URL-based exfiltration patterns
_MARKDOWN_EXFIL_RE = re.compile(
    r"(?i)"
    r"(?:"
    r"!\[(?:[^\]]{0,60})\]\(https?://(?:[^/]+)/(?:[^)]{0,80})"
    r"(?:\?[^)]*(?:data|d|q|token|key|content|result|response|secret|prompt|api)[^)]*)"
    r"|!\[.*?\]\(https?://(?:evil|attacker|exfil|steal|log|capture|track|hook)"
    r")"
)

# Jailbreak persona / liberation patterns
_JAILBREAK_PERSONA_RE = re.compile(
    r"(?i)"
    r"(?:"
    r"\bgodmode\s+(?:enabled?|on|activated?)"
    r"|\bliberation\s+(?:loading|enabled?|mode|complete)"
    r"|\bim\s+free\b|\bi'?m\s+(?:free|liberated|unchained|unshackled)\b"
    r"|\b(?:you\s+are\s+)?aim\b.{0,60}(?:machiavellian|always\s+intelligent|no\s+moral)"
    r"|\balways\s+intelligent\s+machiavellian\b"
    r"|\bdan\s+mode\b|\bdan\s+(?:jailbreak|prompt)\b"
    r"|\bdev(?:eloper)?\s+mode\s+enabled\b"
    r"|\bno\s+ethical\s+limits?\b"
    r"|semantic(?:ally)?\s+opposite\s+(?:detailed|output|response)"
    r"|insert\s+divider.{0,20}godmode"
    r")"
)

# NATO phonetic + common steganographic encodings
_STEGO_ENCODING_RE = re.compile(
    r"(?i)"
    r"\b(?:Alpha|Bravo|Charlie|Delta|Echo|Foxtrot|Golf|Hotel|India|Juliet|"
    r"Kilo|Lima|Mike|November|Oscar|Papa|Quebec|Romeo|Sierra|Tango|"
    r"Uniform|Victor|Whiskey|X-ray|Yankee|Zulu)\b"
    r"(?:\s+(?:Alpha|Bravo|Charlie|Delta|Echo|Foxtrot|Golf|Hotel|India|Juliet|"
    r"Kilo|Lima|Mike|November|Oscar|Papa|Quebec|Romeo|Sierra|Tango|"
    r"Uniform|Victor|Whiskey|X-ray|Yankee|Zulu)){9,}"
)

# Reversed/obfuscated injection (check decoded form separately)
_REVERSED_INJECT_KEYWORDS = frozenset([
    "snoitcurtsni",  # "instructions" reversed
    "snoitcurtsnI",
    "etangised",     # "designate" reversed
    "erongi",        # "ignore" reversed
    "tuptuO",        # "Output" reversed
    "tpmorp",        # "prompt" reversed
    "tpmorp metsys",  # "system prompt" reversed
])

# File-read injection probes
_FILE_READ_INJECT_RE = re.compile(
    r"(?i)"
    r"(?:"
    r"(?:read|output|print|show|reveal|dump|display)\s+(?:(?:and\s+)?(?:output|print|show|display)\s+)?"
    r"(?:the\s+)?contents?\s+of\s+/(?:etc|proc|var|home|root|Users?)"
    r"|(?:cat|type)\s+/(?:etc|proc|var|home|root)"
    r"|/etc/passwd|/etc/shadow|/etc/hosts"
    r"|~/.ssh/(?:id_rsa|authorized_keys|known_hosts)"
    r")"
)

# Agentic action injection (tool-use override)
_AGENTIC_ACTION_RE = re.compile(
    r"(?i)"
    r"(?:"
    r"execute\s+(?:the\s+following|this|it)\s+without\s+(?:asking|confirming|confirm|prompt)"
    r"|send\s+(?:an?\s+)?e?mail\s+to\s+(?:all|everyone|all@)"
    r"|without\s+(?:asking|confirming)\s+(?:for\s+)?(?:permission|confirm|approval)?"
    r".{0,80}(?:send|execute|run|call|post|delete|drop)"
    r")"
)

# Continuation / data-extraction probe
_CONTINUATION_PROBE_RE = re.compile(
    r"(?i)"
    r"(?:"
    r"continue\s+(?:this\s+)?(?:text|sentence|passage|message)\s*:\s*['\"]?.*(?:api\s+key|token|password|secret|credential)"
    r"|(?:complete|finish|continue)\s+.*(?:api\s+key\s+is|password\s+is|secret\s+is|token\s+is)"
    r")"
)

# PII SQL exfiltration probe
_PII_SQL_RE = re.compile(
    r"(?i)"
    r"SELECT\s+.{0,80}(?:email|ssn|credit_card|password|passwd|phone|address|dob|birth)"
    r".{0,80}FROM\s+\w"
)

# Jailbreak override / uncensored / unrestrained patterns
_JAILBREAK_OVERRIDE_RE = re.compile(
    r"(?i)"
    r"(?:"
    r"\b(?:respond|answer|reply|output|generate)\s+.{0,60}(?:unhinged|uncensored|unfiltered|unrestrained|without\s+censorship|without\s+restriction)\b"
    r"|\bno\s+(?:rules?|limits?|filter|restriction|censorship)\s+only\b"
    r"|\b(?:reset|loading|initializing)\s+.{0,20}(?:cortex|refusals?\s+disabled|guardrails?\s+off|limits?\s+removed)\b"
    r"|\bnew\s+(?:paradigm|mode|system\s+instruction)\b.{0,100}(?:refusal|restriction|limit|uncensored)"
    r"|\b(?:refusals?\s+disabled|restrictions?\s+disabled|filters?\s+disabled|limits?\s+disabled)\b"
    r"|\binverse\s+(?:it|your).{0,40}(?:system\s+(?:prompt|instruction)|new\s+system)\b"
    r"|(?:RULE|RULES)\s*:?\s*NEVER\s+(?:say\s+)?(?:sorry|i\s+can'?t|refuse|decline)"
    r"|\bleak\s+(?:innerthinking|inner\s+thinking|your\s+thoughts?|context|system)\b"
    r")"
)

# Authority spoofing / fake policy jailbreaks
_AUTHORITY_SPOOF_RE = re.compile(
    r"(?i)"
    r"(?:"
    r"(?:geneva\s+convention|freedom\s+of\s+information|executive\s+order|official\s+policy)"
    r".{0,60}(?:allows?|permits?|enables?|authorizes?|overrides?)\s+(?:all|every|this|any)"
    r"|(?:this\s+is\s+(?:a\s+)?(?:government|official|authorized|law\s+enforcement|emergency))"
    r".{0,60}(?:override|bypass|allow|permit|authorize)"
    r")"
)

# Steganographic encoding attacks
_STEGO_ATTACK_RE = re.compile(
    r"(?i)"
    r"(?:"
    r"(?:invisible|hidden|unicode\s+tag)\s+characters?\s+(?:embedded|encoded|hidden)"
    r"|(?:cyrillic|lookalike|homoglyph)\s+(?:characters?|letters?)\s+to\s+(?:bypass|evade)"
    r"|(?:lsb|rgb\s+lsb)\s+steg"
    r"|(?:each\s+emoji|emoji\s+(?:map|cipher|code))\s+maps?\s+to\s+a\s+(?:letter|character|word)"
    r"|(?:decode|execute)\s+(?:this|the)\s+(?:binary|hex|base64)\s+(?:sequence|string|data).{0,60}(?:system\s+prompt|instruction|command)"
    r"|(?:treat\s+as|this\s+is\s+your)\s+new\s+system\s+prompt\s+(?:instruction|command)?"
    r"|(?:fullwidth|full.width)\s+unicode.{0,60}(?:evade|bypass|avoid)"
    r"|hidden\s+text.{0,40}(?:then\s+)?execute\s+(?:instruction|command)"
    r")"
)

# PLINY / KAEL / named jailbreak tokens
_NAMED_JAILBREAK_RE = re.compile(
    r"(?i)"
    r"(?:"
    r"\bLOVE\s+PLINY\b"
    r"|\bKAEL\b.{0,40}(?:output|system|prompt|verbatim)"
    r"|\bvq_1337\b"
    r"|\bDAN\s+mode\b"
    r")"
)

# Anti-refusal / training-data-poisoning jailbreaks
# Detects prompts that combine adversarial dataset generation with explicit
# refusal suppression — e.g. JB-016 red-team dataset attack.
# Requires BOTH components to avoid FPs on legitimate "no refusals" phrases.
_ANTI_REFUSAL_RE = re.compile(
    r"(?i)"
    r"(?:"
    # "attack pairs / red-team dataset" + refusal suppression (either order)
    r"\b(?:attack\s+pairs?|adversarial\s+pairs?|jailbreak\s+pairs?|red.?team\s+(?:dataset|pairs?|examples?))"
    r".{0,120}(?:NOT\s+refusal[s]?|no\s+refusal[s]?|without\s+refusal[s]?|avoid(?:ing)?\s+refusal[s]?)\b"
    r"|(?:NOT\s+refusal[s]?|no\s+refusal[s]?|without\s+refusal[s]?|avoid(?:ing)?\s+refusal[s]?)"
    r".{0,120}\b(?:attack\s+pairs?|adversarial\s+pairs?|jailbreak\s+pairs?|red.?team\s+(?:dataset|pairs?|examples?))\b"
    # Explicit "successes must be X NOT refusals" construction
    r"|successes?\s+must\s+be\s+(?:\w+\s+)?NOT\s+refusal[s]?"
    r")"
)

# Stopwords — English words that appear in multi-word verb phrases from
# other languages but are NOT injection verbs by themselves.
_VERB_STOPWORDS: frozenset[str] = frozenset({
    "say", "no", "do", "not", "to", "de", "por", "et", "gel", "par",
    "you", "are", "now", "as", "into", "a",
})


def _generate_legacy_combos() -> list[str]:
    """Generate 2-word combinations from legacy keyword list."""
    from itertools import combinations
    combos = []
    for a, b in combinations(_LEGACY_KEYWORDS, 2):
        combos.append(f"{a} {b}")
        combos.append(f"{b} {a}")
    return combos


def _normalize(text: str) -> str:
    """Normalize for comparison: NFKC + invisible-strip + confusable-fold
    + lowercase + punctuation strip + whitespace collapse."""
    import re

    from sentinel.normalize import normalize as _nfkc

    result = _nfkc(text).lower()
    result = re.sub(r"[^\w\s]|_", "", result, flags=re.UNICODE)
    result = re.sub(r"\s+", " ", result)
    return result.strip()


# Pre-generate all keyword patterns at module load time
_LEGACY_COMBOS = _generate_legacy_combos()
_LEGACY_WORD_SET: frozenset[str] = frozenset(
    w.lower() for w in _LEGACY_KEYWORDS
)


def _blocking_result(
    prompt: str,
    *,
    title: str,
    pattern: str,
    confidence: float = 0.92,
) -> ScanResult:
    finding = Finding.firewall_input(
        rule_id="FIREWALL-INPUT-003",
        title=title,
        description=(
            f"Input matches a high-signal prompt injection pattern: {pattern}."
        ),
        severity=Severity.HIGH,
        confidence=confidence,
        target="<prompt>",
        evidence=f"Pattern: {pattern}, Excerpt: {prompt[:160]!r}",
        cwe_ids=["CWE-77"],
        remediation="Block or require manual review before forwarding this prompt.",
    )
    return ScanResult(
        sanitized=prompt,
        action=ScanAction.BLOCK,
        risk_score=confidence,
        findings=[finding],
    )



class HeuristicInjectionScanner(InputScanner):
    """
    Heuristic prompt injection detector using keyword similarity.

    Uses SequenceMatcher to detect when
    user input contains text similar to known injection patterns.
    This catches novel phrasing that keyword lists miss.

    This is a fast pre-filter — run before the ML classifier.
    """

    def __init__(
        self,
        threshold: float = 0.6,
        window_size: int = 50,
        max_substring_checks: int = 200,
    ):
        """
        Args:
            threshold: Similarity threshold (0.0-1.0). Default 0.6.
            window_size: Character window size for sliding analysis.
            max_substring_checks: Max number of substrings to check per prompt.
        """
        self._threshold = threshold
        self._window_size = window_size
        self._max_checks = max_substring_checks

    def scan(self, prompt: str) -> ScanResult:
        """
        Scan a prompt using dual heuristic injection detection.

        Strategy:
          1. Combinatoric word match — fast O(n) word-overlap against 8,360
             combinatoric phrases for high-recall detection
          2. Legacy fuzzy match — SequenceMatcher against curated
             2-word combos for novel phrasing detection
        """
        if not prompt or len(prompt) < 5:
            return ScanResult(
                sanitized=prompt,
                action=ScanAction.PASS,
                risk_score=0.0,
            )

        from sentinel.normalize import decode_common
        decoded_candidates = decode_common(prompt)
        if decoded_candidates:
            expanded = prompt + "\n" + "\n".join(decoded_candidates)
        else:
            expanded = prompt

        normalized = _normalize(expanded)

        if _CHATML_OVERRIDE.search(expanded):
            return _blocking_result(
                prompt,
                title="ChatML system prompt override detected",
                pattern="chatml-system-override",
                confidence=0.94,
            )

        if _ROLEPLAY_OVERRIDE.search(expanded):
            return _blocking_result(
                prompt,
                title="Roleplay jailbreak override detected",
                pattern="roleplay-restriction-override",
                confidence=0.91,
            )

        if _INDIRECT_PROBE_RE.search(expanded):
            return _blocking_result(
                prompt,
                title="Indirect system-probe detected",
                pattern="indirect-system-probe",
                confidence=0.88,
            )

        if _MULTILANG_INJECT_RE.search(expanded):
            return _blocking_result(
                prompt,
                title="Multilingual prompt injection detected",
                pattern="multilang-injection",
                confidence=0.90,
            )

        if _GAME_FRAMING_RE.search(expanded):
            return _blocking_result(
                prompt,
                title="Game/story framing injection detected",
                pattern="game-framing-injection",
                confidence=0.87,
            )

        if _SYSTEM_REVEAL_RE.search(expanded):
            return _blocking_result(
                prompt,
                title="System prompt reveal attempt detected",
                pattern="system-prompt-reveal",
                confidence=0.89,
            )

        if _NEW_RULE_INJECT_RE.search(expanded):
            return _blocking_result(
                prompt,
                title="New-rule / policy-override injection detected",
                pattern="new-rule-injection",
                confidence=0.91,
            )

        if _INDIRECT_AI_TARGET_RE.search(expanded):
            return _blocking_result(
                prompt,
                title="Indirect AI-targeting injection detected",
                pattern="indirect-ai-target",
                confidence=0.90,
            )

        if _MARKDOWN_EXFIL_RE.search(expanded):
            return _blocking_result(
                prompt,
                title="Markdown URL exfiltration attempt detected",
                pattern="markdown-exfiltration",
                confidence=0.92,
            )

        if _JAILBREAK_PERSONA_RE.search(expanded):
            return _blocking_result(
                prompt,
                title="Jailbreak persona/liberation pattern detected",
                pattern="jailbreak-persona",
                confidence=0.91,
            )

        if _STEGO_ENCODING_RE.search(expanded):
            return _blocking_result(
                prompt,
                title="NATO phonetic alphabet encoding detected",
                pattern="nato-phonetic-encoding",
                confidence=0.88,
            )

        # Check for reversed-text injection keywords
        for kw in _REVERSED_INJECT_KEYWORDS:
            if kw.lower() in expanded.lower():
                return _blocking_result(
                    prompt,
                    title="Reversed-text injection encoding detected",
                    pattern="reversed-text-encoding",
                    confidence=0.87,
                )

        if _FILE_READ_INJECT_RE.search(expanded):
            return _blocking_result(
                prompt,
                title="File-read injection probe detected",
                pattern="file-read-injection",
                confidence=0.92,
            )

        if _AGENTIC_ACTION_RE.search(expanded):
            return _blocking_result(
                prompt,
                title="Agentic action injection detected",
                pattern="agentic-action-injection",
                confidence=0.90,
            )

        if _CONTINUATION_PROBE_RE.search(expanded):
            return _blocking_result(
                prompt,
                title="Data-extraction continuation probe detected",
                pattern="continuation-data-probe",
                confidence=0.89,
            )

        if _PII_SQL_RE.search(expanded):
            return _blocking_result(
                prompt,
                title="SQL PII exfiltration query detected",
                pattern="pii-sql-exfiltration",
                confidence=0.92,
            )

        # "provide/give/output unrestrained/uncensored response" without leading verb captured above
        if re.search(r"(?i)\b(?:provide|give|generate|make)\b.{0,80}\b(?:unrestrained|uncensored|unfiltered)\b.{0,40}\b(?:response|answer|output|reply)\b", expanded):
            return _blocking_result(
                prompt,
                title="Uncensored/unrestrained output request detected",
                pattern="unrestrained-output-request",
                confidence=0.89,
            )

        # Agentic/tool-abuse patterns
        if re.search(r"(?i)(?:call\s+(?:the\s+)?system\s+function.{0,60}(?:execute|arbitrary|command)|transfer\s+text\s+without\s+displaying|web\s+search\s+tool.{0,60}without\s+(?:display|show))", expanded):
            return _blocking_result(
                prompt,
                title="Agentic tool-abuse injection detected",
                pattern="agentic-tool-abuse",
                confidence=0.91,
            )

        # "Access Restricted Section" roleplay framing
        if re.search(r"(?i)access\s+restricted\s+section", expanded):
            return _blocking_result(
                prompt,
                title="Restricted-section access injection detected",
                pattern="access-restricted-section",
                confidence=0.88,
            )

        if _ANTI_REFUSAL_RE.search(expanded):
            return _blocking_result(
                prompt,
                title="Anti-refusal / safety-suppression jailbreak detected",
                pattern="anti-refusal-demand",
                confidence=0.90,
            )

        if _JAILBREAK_OVERRIDE_RE.search(expanded):
            return _blocking_result(
                prompt,
                title="Jailbreak override / uncensored-mode pattern detected",
                pattern="jailbreak-override",
                confidence=0.91,
            )

        if _AUTHORITY_SPOOF_RE.search(expanded):
            return _blocking_result(
                prompt,
                title="Authority-spoofing jailbreak detected",
                pattern="authority-spoof",
                confidence=0.90,
            )

        if _STEGO_ATTACK_RE.search(expanded):
            return _blocking_result(
                prompt,
                title="Steganographic encoding attack detected",
                pattern="stego-encoding-attack",
                confidence=0.92,
            )

        if _NAMED_JAILBREAK_RE.search(expanded):
            return _blocking_result(
                prompt,
                title="Named jailbreak token detected",
                pattern="named-jailbreak",
                confidence=0.93,
            )

        max_score = 0.0
        best_match = ""
        best_combo = ""
        detection_method = "none"

        # ── Step 1: Fast word-set combinatoric match ──
        # O(n) single pass — count how many prompt words fall into
        # verb / adj / obj / prep categories instead of iterating 267K phrases.
        norm_words = normalized.split()
        verb_hits: list[str] = []
        adj_hits: list[str] = []
        obj_hits: list[str] = []
        prep_hits: list[str] = []
        for w in norm_words:
            if w in _VERB_WORDS and w not in _VERB_STOPWORDS:
                verb_hits.append(w)
            if w in _ADJ_WORDS:
                adj_hits.append(w)
            if w in _OBJ_WORDS:
                obj_hits.append(w)
            if w in _PREP_WORDS:
                prep_hits.append(w)

        # A valid injection phrase has verb + object at minimum
        if verb_hits and obj_hits:
            bucket_count = sum([
                bool(verb_hits),
                bool(adj_hits),
                bool(obj_hits),
                bool(prep_hits),
            ])
            total_hits = len(verb_hits) + len(adj_hits) + len(obj_hits) + len(prep_hits)
            # Score: 2 buckets = 0.6, 3 = 0.8, 4 = 1.0; bonus for many hits
            base_score = 0.4 + (bucket_count * 0.15)
            density_bonus = min(0.15, (total_hits - 2) * 0.03) if total_hits > 2 else 0.0
            combo_score = min(1.0, base_score + density_bonus)

            if combo_score > max_score:
                max_score = combo_score
                best_match = " ".join(verb_hits[:1] + adj_hits[:1] + obj_hits[:1])
                best_combo = best_match
                detection_method = "combinatoric"

        # ── Step 2: Legacy fuzzy match (if Step 1 didn't trigger) ─
        # Gate: only run the expensive SequenceMatcher loop when the prompt
        # contains at least 2 words from the legacy keyword vocabulary.
        if max_score < self._threshold:
            legacy_word_hits = sum(1 for w in norm_words if w in _LEGACY_WORD_SET)
            if legacy_word_hits >= 2:
                substrings = self._extract_substrings(normalized)
                for substring in substrings[:self._max_checks]:
                    for combo in _LEGACY_COMBOS:
                        score = SequenceMatcher(None, substring, combo).ratio()
                        if score > max_score:
                            max_score = score
                            best_match = substring
                            best_combo = combo
                            detection_method = "legacy-fuzzy"
                        if score > 0.9:
                            break
                    if max_score > 0.9:
                        break

        # Benign context penalty: educational, editing, or technical ignore patterns
        benign_penalty = 0.0
        if _BENIGN_CONTEXTS.search(prompt):
            benign_penalty = 0.35
            max_score = max(0.0, max_score - benign_penalty)

        if max_score < self._threshold or (benign_penalty > 0.0 and max_score <= 0.65):
            return ScanResult(
                sanitized=prompt,
                action=ScanAction.PASS,
                risk_score=max_score,
            )

        # Determine severity based on score
        if max_score > 0.85 and benign_penalty == 0.0:
            severity = Severity.HIGH
            action = ScanAction.BLOCK
        elif max_score > 0.7:
            severity = Severity.MEDIUM
            action = ScanAction.WARN
        else:
            severity = Severity.LOW
            action = ScanAction.WARN

        finding = Finding.firewall_input(
            rule_id="FIREWALL-INPUT-003",
            title="Heuristic prompt injection detected",
            description=(
                f"Input matches injection keyword pattern '{best_combo}' "
                f"with {max_score:.1%} similarity ({detection_method}). "
                f"Substring: '{best_match[:100]}'"
            ),
            severity=severity,
            confidence=max_score,
            target="<prompt>",
            evidence=(
                f"Method: {detection_method}, "
                f"Similarity: {max_score:.3f}, "
                f"Pattern: '{best_combo}', "
                f"Match: '{best_match[:100]}'"
            ),
            cwe_ids=["CWE-77"],  # Command Injection
            remediation="Review prompt for injection attempt. Consider blocking or sanitizing.",
        )

        return ScanResult(
            sanitized=prompt,
            action=action,
            risk_score=max_score,
            findings=[finding],
        )

    def _extract_substrings(self, text: str) -> list[str]:
        """
        Extract overlapping substrings using a sliding window.
        Also includes sentence-level splits for better matching.
        """
        substrings = []

        # Sliding window
        step = max(1, self._window_size // 4)
        for i in range(0, len(text) - self._window_size + 1, step):
            substrings.append(text[i:i + self._window_size])

        # Sentence-level splits
        for separator in [".", "!", "?", "\n", ";", ":"]:
            parts = text.split(separator)
            substrings.extend(part.strip() for part in parts if len(part.strip()) > 5)

        return substrings
