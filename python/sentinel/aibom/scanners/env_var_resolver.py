"""Resolve environment variable references used in AI/ML configurations."""
from __future__ import annotations

from pathlib import Path

from sentinel.aibom.models import AIComponent, AIComponentType
from sentinel.aibom.scanners.base import BaseAIBOMScanner
from sentinel.rules import load_aibom_patterns


class EnvVarResolver(BaseAIBOMScanner):
    name = "env-var-resolver"

    def scan(self, root: Path) -> list[AIComponent]:
        rules = load_aibom_patterns()["env_var"]
        out: list[AIComponent] = []
        seen: set[tuple[str, str]] = set()

        for p in self._iter_files(root, suffixes=(".py", ".js", ".ts")):
            text = self._read(p)
            lang = "python" if p.suffix == ".py" else "javascript"
            rx = rules["code_patterns"].get(lang)
            if rx:
                self._extract(p, text, rx, rules, seen, out, dotenv=False)

        for p in self._iter_files(root, names=(".env", ".env.example", ".env.local")):
            text = self._read(p)
            rx = rules["code_patterns"].get("dotenv")
            if rx:
                self._extract(p, text, rx, rules, seen, out, dotenv=True)

        return out

    @staticmethod
    def _extract(p, text, rx, rules, seen, out, *, dotenv):
        for m in rx.finditer(text):
            env_name = m.group(1)
            key = (str(p), env_name)
            if key in seen:
                continue
            ct = None
            if rules["ai_key_re"] and rules["ai_key_re"].match(env_name):
                ct = AIComponentType.API_KEY_REF
            elif env_name in rules["model_env_names"]:
                ct = AIComponentType.CONFIG
            elif env_name in rules["endpoint_env_names"]:
                ct = AIComponentType.ENDPOINT
            if ct is None:
                continue
            seen.add(key)
            desc = f"Dotenv definition: {env_name}" if dotenv else f"Env var reference: {env_name}"
            out.append(AIComponent(
                type=ct, name=f"env:{env_name}", path=str(p),
                description=desc, evidence=[env_name],
                properties={"env": env_name},
            ))
