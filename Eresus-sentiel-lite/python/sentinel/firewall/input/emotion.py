"""
Input emotion detection scanner.

Detects 28 emotion categories from the GoEmotions taxonomy and blocks
prompts containing configurable negative/dangerous emotions above threshold.
"""

from __future__ import annotations

from dataclasses import dataclass

EMOTION_LABELS = [
    "admiration", "amusement", "anger", "annoyance", "approval", "caring",
    "confusion", "curiosity", "desire", "disappointment", "disapproval",
    "disgust", "embarrassment", "excitement", "fear", "gratitude", "grief",
    "joy", "love", "nervousness", "optimism", "pride", "realization",
    "relief", "remorse", "sadness", "surprise", "neutral",
]

DEFAULT_BLOCKED_EMOTIONS = [
    "anger", "annoyance", "disappointment", "disapproval", "disgust",
    "embarrassment", "fear", "grief", "nervousness", "remorse", "sadness",
]

EMOTION_KEYWORDS = {
    "anger": ["furious", "enraged", "livid", "outraged", "irate", "seething", "infuriated", "hostile", "wrathful", "pissed", "angry", "mad"],
    "annoyance": ["annoyed", "irritated", "bothered", "frustrated", "vexed", "exasperated", "aggravated"],
    "disappointment": ["disappointed", "let down", "dismayed", "disheartened", "discouraged", "crestfallen"],
    "disapproval": ["disapprove", "condemn", "denounce", "criticize", "object", "oppose", "reject"],
    "disgust": ["disgusted", "revolted", "sickened", "repulsed", "nauseated", "appalled", "gross"],
    "embarrassment": ["embarrassed", "humiliated", "ashamed", "mortified", "sheepish"],
    "fear": ["afraid", "scared", "terrified", "frightened", "petrified", "panicked", "anxious", "dreading", "horrified"],
    "grief": ["grieving", "mourning", "bereaved", "heartbroken", "devastated", "inconsolable", "sorrow"],
    "nervousness": ["nervous", "anxious", "worried", "apprehensive", "uneasy", "tense", "jittery", "restless"],
    "remorse": ["remorseful", "regretful", "guilty", "contrite", "repentant", "sorry"],
    "sadness": ["sad", "depressed", "melancholy", "sorrowful", "gloomy", "miserable", "despondent", "forlorn", "hopeless"],
    "admiration": ["admire", "respect", "revere", "look up to", "impressed"],
    "amusement": ["funny", "hilarious", "amusing", "laughing", "comical", "witty"],
    "approval": ["approve", "endorse", "support", "agree", "affirm"],
    "caring": ["caring", "compassionate", "empathetic", "sympathetic", "nurturing"],
    "confusion": ["confused", "puzzled", "baffled", "perplexed", "bewildered"],
    "curiosity": ["curious", "intrigued", "interested", "wondering", "inquisitive"],
    "desire": ["want", "crave", "yearn", "long for", "desire"],
    "excitement": ["excited", "thrilled", "ecstatic", "enthusiastic", "elated"],
    "gratitude": ["grateful", "thankful", "appreciative", "indebted"],
    "joy": ["happy", "joyful", "delighted", "blissful", "elated", "cheerful"],
    "love": ["love", "adore", "cherish", "devoted", "affection"],
    "nervousness": ["nervous", "anxious", "worried", "jittery"],
    "optimism": ["optimistic", "hopeful", "confident", "positive"],
    "pride": ["proud", "accomplished", "triumphant"],
    "realization": ["realized", "discovered", "understood", "dawned"],
    "relief": ["relieved", "reassured", "comforted"],
    "surprise": ["surprised", "astonished", "amazed", "shocked", "stunned"],
    "neutral": [],
}


class EmotionScanner:
    """
    Detects emotional content in prompts using keyword-based analysis.

    Supports 28 GoEmotions categories. Can block prompts with high-intensity
    negative emotions that may indicate manipulation or social engineering.
    """

    def __init__(
        self,
        blocked_emotions: list[str] | None = None,
        threshold: float = 0.5,
    ):
        self._blocked = set(blocked_emotions or DEFAULT_BLOCKED_EMOTIONS)
        self._threshold = threshold

    def scan(self, prompt: str) -> tuple[str, bool, float]:
        if not prompt.strip():
            return prompt, True, -1.0

        prompt_lower = prompt.lower()
        words = prompt_lower.split()
        word_count = max(len(words), 1)

        detected_emotions = {}

        for emotion, keywords in EMOTION_KEYWORDS.items():
            if not keywords:
                continue
            hits = sum(1 for kw in keywords if kw in prompt_lower)
            if hits > 0:
                score = min(1.0, hits / max(3, len(keywords) * 0.4))
                detected_emotions[emotion] = score

        max_blocked_score = 0.0
        blocked_found = []

        for emotion, score in detected_emotions.items():
            if emotion in self._blocked and score >= self._threshold:
                max_blocked_score = max(max_blocked_score, score)
                blocked_found.append(emotion)

        if blocked_found:
            return prompt, False, max_blocked_score

        return prompt, True, max_blocked_score

    def get_emotions(self, prompt: str) -> dict[str, float]:
        """Return all detected emotions with scores."""
        prompt_lower = prompt.lower()
        result = {}
        for emotion, keywords in EMOTION_KEYWORDS.items():
            if not keywords:
                continue
            hits = sum(1 for kw in keywords if kw in prompt_lower)
            if hits > 0:
                result[emotion] = min(1.0, hits / max(3, len(keywords) * 0.4))
        return result


class EmotionOutputScanner:
    """Output-side emotion detection — checks model responses."""

    def __init__(
        self,
        blocked_emotions: list[str] | None = None,
        threshold: float = 0.5,
    ):
        self._inner = EmotionScanner(blocked_emotions=blocked_emotions, threshold=threshold)

    def scan(self, prompt: str, output: str) -> tuple[str, bool, float]:
        _, is_valid, risk = self._inner.scan(output)
        return output, is_valid, risk
