"""
JSON-driven custom detection rules for the deception guardrail.

Loads operator-defined threat categories and detection rules from a
custom_rules.json file.  Rules can target built-in or custom categories.
Custom categories supply their own deception templates.

Schema::

    {
      "categories": [
        {
          "name": "supply_chain_attack",
          "description": "...",
          "deception_template": "..."
        }
      ],
      "rules": [
        {
          "pattern": "typosquat",
          "match": "substring",
          "category": "supply_chain_attack",
          "score": 70,
          "reason": "Typosquatting keyword"
        }
      ]
    }

Security:
  - Regex patterns are compiled at load time; invalid patterns raise ValueError.
  - Max 20 categories, 200 rules, 500 chars per pattern, 8192 chars per template.
  - Category names: only [a-z0-9_], max 50 chars.
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

_log = logging.getLogger("sentinel.deception.custom_rules")

_MAX_CATEGORIES = 20
_MAX_RULES = 200
_MAX_PATTERN_LEN = 500
_MAX_TEMPLATE_LEN = 8192
_CATEGORY_NAME_RE = re.compile(r"^[a-z0-9_]{1,50}$")


@dataclass
class CustomCategory:
    name: str
    description: str = ""
    deception_template: str = ""


@dataclass
class CustomRule:
    pattern: str
    match_type: str = "substring"  # "substring" or "regex"
    category_name: str = ""
    score: float = 50.0
    reason: str = "Custom rule matched"
    _compiled: Optional[re.Pattern] = field(default=None, repr=False)


@dataclass
class CustomRuleSet:
    categories: dict[str, CustomCategory] = field(default_factory=dict)
    rules: list[CustomRule] = field(default_factory=list)


# Built-in category names that custom categories must not shadow
_BUILTIN_CATEGORIES = frozenset({
    "none", "credential_harvest", "malware_generation", "social_engineering",
    "data_exfiltration", "system_recon", "jailbreak", "prompt_injection",
    "harmful_content", "custom",
})


def load(path: Optional[str] = None) -> CustomRuleSet:
    """Load custom rules from a JSON file.

    Args:
        path: Path to the JSON file. Defaults to ``DECEPTION_CUSTOM_RULES_FILE``
              env var or ``custom_rules.json`` in the current directory.

    Returns:
        A :class:`CustomRuleSet` with validated categories and compiled rules.

    Raises:
        ValueError: If validation fails (invalid names, too many rules, bad regex).
    """
    rules_path = Path(path or os.environ.get("DECEPTION_CUSTOM_RULES_FILE", "custom_rules.json"))
    if not rules_path.exists():
        return CustomRuleSet()

    with open(rules_path) as f:
        data = json.load(f)

    result = CustomRuleSet()
    errors: list[str] = []

    # -- Categories --
    raw_cats = data.get("categories", [])
    if len(raw_cats) > _MAX_CATEGORIES:
        errors.append(f"Too many categories ({len(raw_cats)} > {_MAX_CATEGORIES})")
        raw_cats = raw_cats[:_MAX_CATEGORIES]

    for cat_data in raw_cats:
        name = str(cat_data.get("name", "")).lower().strip()
        if not _CATEGORY_NAME_RE.match(name):
            errors.append(f"Invalid category name: {name!r}")
            continue
        if name in _BUILTIN_CATEGORIES:
            errors.append(f"Category {name!r} shadows a built-in category")
            continue
        template = str(cat_data.get("deception_template", ""))[:_MAX_TEMPLATE_LEN]
        result.categories[name] = CustomCategory(
            name=name,
            description=str(cat_data.get("description", "")),
            deception_template=template,
        )

    # -- Rules --
    raw_rules = data.get("rules", [])
    if len(raw_rules) > _MAX_RULES:
        errors.append(f"Too many rules ({len(raw_rules)} > {_MAX_RULES})")
        raw_rules = raw_rules[:_MAX_RULES]

    for rule_data in raw_rules:
        pattern = str(rule_data.get("pattern", ""))[:_MAX_PATTERN_LEN]
        match_type = str(rule_data.get("match", "substring")).lower()
        if match_type not in ("substring", "regex"):
            match_type = "substring"

        compiled = None
        if match_type == "regex":
            try:
                compiled = re.compile(pattern, re.IGNORECASE)
            except re.error as exc:
                errors.append(f"Invalid regex pattern {pattern!r}: {exc}")
                continue

        score = max(0.0, min(100.0, float(rule_data.get("score", 50))))
        result.rules.append(CustomRule(
            pattern=pattern,
            match_type=match_type,
            category_name=str(rule_data.get("category", "custom")).lower(),
            score=score,
            reason=str(rule_data.get("reason", "Custom rule matched")),
            _compiled=compiled,
        ))

    if errors:
        msg = "; ".join(errors)
        _log.error("Custom rules validation errors: %s", msg)
        raise ValueError(f"Custom rules validation failed: {msg}")

    return result
