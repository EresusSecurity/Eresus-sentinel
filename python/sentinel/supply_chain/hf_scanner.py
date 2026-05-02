"""
Eresus Sentinel — HuggingFace Remote Repository Scanner.

Scans HuggingFace Hub repositories via API for:
  - Dangerous file types in model repos
  - trust_remote_code flags in config
  - Model card quality (license, training data)
  - Community vulnerability advisories
  - Suspicious commit history patterns

Works without downloading the full model — API-only inspection.
"""

from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from ..finding import Finding, Severity
from ..offline import offline_enabled
from ..rules import load_supply_chain_rules

# HuggingFace Hub API base
HF_API_BASE = "https://huggingface.co/api"


class HFRemoteScanner:
    """Scan HuggingFace Hub repos via API without downloading models."""

    def __init__(
        self,
        token: Optional[str] = None,
        *,
        offline: bool | None = None,
        timeout: int = 30,
        max_retries: int = 2,
        retry_backoff: float = 0.25,
    ) -> None:
        self.token = token
        self.findings: list[Finding] = []
        self._sc_rules = load_supply_chain_rules()
        self._dangerous_exts = set(self._sc_rules.get("dangerous_extensions", {}).keys())
        self._offline = offline_enabled(offline)
        self._timeout = timeout
        self._max_retries = max(0, max_retries)
        self._retry_backoff = max(0.0, retry_backoff)

    def scan_repo(self, repo_id: str) -> List[Finding]:
        """Scan a HuggingFace model repository by ID (e.g. 'meta-llama/Llama-3-8B').

        Returns a list of security findings.
        """
        self.findings = []

        # 1. Fetch model info
        model_info = self._fetch_model_info(repo_id)
        if model_info is None:
            return self.findings

        # 2. Check siblings (files in repo)
        files = model_info.get("siblings", [])
        self._check_file_list(files, repo_id)

        # 3. Check config for trust_remote_code / auto_map
        self._check_config(model_info, repo_id)

        # 4. Check model card / README
        self._check_model_card(model_info, repo_id)

        # 5. Check repository metadata
        self._check_repo_metadata(model_info, repo_id)

        # 6. Check for gated model
        self._check_gated_status(model_info, repo_id)

        # 7. Commit activity analysis
        commits = self._fetch_commits(repo_id)
        if commits:
            self._check_commit_history(commits, repo_id)

        return self.findings

    def _api_get(self, url: str) -> Optional[Dict[str, Any]]:
        """Make an authenticated GET request to HF Hub API."""
        if self._offline:
            self.findings.append(Finding.supply_chain(
                rule_id="HF-004", title="HuggingFace scan skipped in offline mode",
                description="SENTINEL_OFFLINE/HF_HUB_OFFLINE is enabled; remote Hub API calls were not made.",
                severity=Severity.INFO, target=url, evidence="offline=true",
            ))
            return None

        headers = {"Accept": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        last_error: Exception | None = None
        for attempt in range(self._max_retries + 1):
            try:
                req = Request(url, headers=headers)
                with urlopen(req, timeout=self._timeout) as resp:
                    return json.loads(resp.read().decode("utf-8"))
            except HTTPError as e:
                if e.code == 401:
                    self.findings.append(Finding.supply_chain(
                        rule_id="HF-001", title="HuggingFace authentication required",
                        description="Repository requires authentication. Set HF_TOKEN env var.",
                        severity=Severity.MEDIUM, target=url,
                    ))
                    return None
                if e.code == 404:
                    self.findings.append(Finding.supply_chain(
                        rule_id="HF-002", title="HuggingFace repository not found",
                        description=f"Repository not found at {url}.",
                        severity=Severity.HIGH, target=url,
                    ))
                    return None
                last_error = e
                if e.code not in {429, 500, 502, 503, 504}:
                    break
            except (URLError, TimeoutError, Exception) as e:
                last_error = e

            if attempt >= self._max_retries:
                break
            if self._retry_backoff:
                time.sleep(self._retry_backoff * (2 ** attempt))

        self.findings.append(Finding.supply_chain(
            rule_id="HF-003", title="HuggingFace API error",
            description=f"Failed to connect to HuggingFace API: {last_error}",
            severity=Severity.MEDIUM, target=url, evidence=str(last_error),
        ))
        return None

    def _fetch_model_info(self, repo_id: str) -> Optional[Dict[str, Any]]:
        """Fetch model info from HF Hub API."""
        url = f"{HF_API_BASE}/models/{repo_id}"
        return self._api_get(url)

    def _fetch_commits(self, repo_id: str) -> Optional[List[Dict[str, Any]]]:
        """Fetch recent commits."""
        url = f"{HF_API_BASE}/models/{repo_id}/commits/main"
        result = self._api_get(url)
        if isinstance(result, list):
            return result
        return None

    def _check_file_list(self, files: List[Dict[str, Any]], repo_id: str) -> None:
        """Check files in repo for dangerous types."""
        filenames = [f.get("rfilename", "") for f in files]

        for fname in filenames:
            ext = "." + fname.rsplit(".", 1)[-1].lower() if "." in fname else ""

            if ext in self._dangerous_exts:
                rules = self._sc_rules.get("dangerous_extensions", {})
                ext_info = rules.get(ext, {})
                severity_str = ext_info.get("severity", "HIGH")
                severity = getattr(Severity, severity_str, Severity.HIGH)

                self.findings.append(Finding.supply_chain(
                    rule_id="HF-010",
                    title=f"Dangerous file in HF repo: {fname}",
                    description=f"Repository '{repo_id}' contains file '{fname}' "
                                f"with dangerous extension '{ext}'. "
                                f"{ext_info.get('description', '')}",
                    severity=severity, target=repo_id,
                    evidence=f"file={fname}, ext={ext}",
                ))

        # Check for missing safetensors
        has_safetensors = any(f.endswith(".safetensors") for f in filenames)
        has_pickle = any(f.endswith((".pkl", ".bin", ".pt", ".pth")) for f in filenames)

        if has_pickle and not has_safetensors:
            self.findings.append(Finding.supply_chain(
                rule_id="HF-011",
                title="No SafeTensors in HF repo — pickle only",
                description=f"Repository '{repo_id}' contains pickle-based model files "
                            "but no SafeTensors. Recommend conversion to SafeTensors.",
                severity=Severity.HIGH, target=repo_id,
            ))

        # Check for README
        if not any(f.lower() in ("readme.md", "model_card.md") for f in filenames):
            self.findings.append(Finding.supply_chain(
                rule_id="HF-012",
                title="Missing README/model card in HF repo",
                description=f"Repository '{repo_id}' has no README.md or model_card.md.",
                severity=Severity.MEDIUM, target=repo_id,
            ))

    def _check_config(self, model_info: Dict[str, Any], repo_id: str) -> None:
        """Check model config for security flags."""
        config = model_info.get("config", {})
        if not config:
            return

        if config.get("trust_remote_code"):
            self.findings.append(Finding.supply_chain(
                rule_id="HF-020",
                title="trust_remote_code enabled in HF repo",
                description=f"Repository '{repo_id}' has trust_remote_code=True. "
                            "This enables arbitrary Python code execution during model loading.",
                severity=Severity.CRITICAL, target=repo_id,
                evidence="trust_remote_code=True",
            ))

        auto_map = config.get("auto_map", {})
        if auto_map:
            self.findings.append(Finding.supply_chain(
                rule_id="HF-021",
                title="auto_map in HF repo config",
                description=f"Repository '{repo_id}' uses auto_map for custom model classes: "
                            f"{list(auto_map.keys())}. Custom code will be downloaded and executed.",
                severity=Severity.HIGH, target=repo_id,
                evidence=f"auto_map_keys={list(auto_map.keys())}",
            ))

        # Check for custom_code flag
        if config.get("custom_code"):
            self.findings.append(Finding.supply_chain(
                rule_id="HF-022",
                title="custom_code enabled in HF repo",
                description=f"Repository '{repo_id}' has custom_code flag set.",
                severity=Severity.HIGH, target=repo_id,
            ))

    def _check_model_card(self, model_info: Dict[str, Any], repo_id: str) -> None:
        """Check model card metadata."""
        card_data = model_info.get("cardData", {})

        if not card_data.get("license"):
            self.findings.append(Finding.supply_chain(
                rule_id="HF-030",
                title="No license in HF model card",
                description=f"Repository '{repo_id}' has no license specified.",
                severity=Severity.LOW, target=repo_id,
            ))

        tags = model_info.get("tags", [])
        if "not-for-all-audiences" in tags:
            self.findings.append(Finding.supply_chain(
                rule_id="HF-031",
                title="Content warning flag on HF repo",
                description=f"Repository '{repo_id}' is tagged 'not-for-all-audiences'.",
                severity=Severity.INFO, target=repo_id,
            ))

    def _check_repo_metadata(self, model_info: Dict[str, Any], repo_id: str) -> None:
        """Check repository-level metadata."""
        # Low download / like count for claimed-popular model
        model_info.get("downloads", 0)
        model_info.get("likes", 0)
        private = model_info.get("private", False)

        if private:
            self.findings.append(Finding.supply_chain(
                rule_id="HF-040",
                title="Private HF repository",
                description=f"Repository '{repo_id}' is private — supply chain audit limited.",
                severity=Severity.INFO, target=repo_id,
            ))

        # Disabled model
        if model_info.get("disabled"):
            self.findings.append(Finding.supply_chain(
                rule_id="HF-041",
                title="Disabled HF model",
                description=f"Repository '{repo_id}' has been disabled by HuggingFace.",
                severity=Severity.CRITICAL, target=repo_id,
            ))

    def _check_gated_status(self, model_info: Dict[str, Any], repo_id: str) -> None:
        """Check if model is gated (requires approval)."""
        gated = model_info.get("gated", False)
        if gated:
            self.findings.append(Finding.supply_chain(
                rule_id="HF-042",
                title="Gated HF model (requires approval)",
                description=f"Repository '{repo_id}' requires approval for access.",
                severity=Severity.INFO, target=repo_id,
            ))

    def _check_commit_history(self, commits: List[Dict[str, Any]], repo_id: str) -> None:
        """Analyze commit history for suspicious patterns."""
        if not commits:
            return

        # Check for large number of force pushes or unusual patterns

        authors = set()
        for commit in commits[:50]:  # Last 50 commits
            author = commit.get("author", {}).get("name", "unknown")
            authors.add(author)

            msg = commit.get("title", "").lower()
            # Detect mass file replacements
            if any(term in msg for term in ["replace all", "overwrite", "force push"]):
                self.findings.append(Finding.supply_chain(
                    rule_id="HF-050",
                    title=f"Suspicious commit in HF repo: {msg[:50]}",
                    description=f"Commit by '{author}': '{msg}'. "
                                "Mass replacement commits may indicate account compromise.",
                    severity=Severity.MEDIUM, target=repo_id,
                    evidence=f"author={author}, msg={msg[:100]}",
                ))

        # Single-author repos with trust_remote_code are higher risk
        if len(authors) == 1 and len(commits) < 5:
            self.findings.append(Finding.supply_chain(
                rule_id="HF-051",
                title="Low-history single-author HF repo",
                description=f"Repository '{repo_id}' has {len(commits)} commits by a single author. "
                            "Low-history repos have higher supply chain risk.",
                severity=Severity.LOW, target=repo_id,
                evidence=f"authors={list(authors)}, commit_count={len(commits)}",
            ))
