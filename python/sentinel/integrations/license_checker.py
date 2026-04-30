"""
License compatibility checker for ML models.

Checks model license metadata against a configurable compatibility policy.
Flags restrictive, missing, or incompatible licenses.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from sentinel.finding import Finding, Severity

_log = logging.getLogger("sentinel.integrations.license_checker")


class LicenseRisk(str, Enum):
    PERMISSIVE = "permissive"
    WEAK_COPYLEFT = "weak_copyleft"
    STRONG_COPYLEFT = "strong_copyleft"
    RESTRICTIVE = "restrictive"
    UNKNOWN = "unknown"


@dataclass
class LicenseInfo:
    spdx_id: str
    name: str
    risk: LicenseRisk
    commercial_ok: bool = True
    requires_attribution: bool = False
    requires_share_alike: bool = False


# Common ML model licenses
_LICENSE_DB: dict[str, LicenseInfo] = {
    "apache-2.0": LicenseInfo("Apache-2.0", "Apache License 2.0", LicenseRisk.PERMISSIVE, True, True, False),
    "mit": LicenseInfo("MIT", "MIT License", LicenseRisk.PERMISSIVE, True, True, False),
    "bsd-2-clause": LicenseInfo("BSD-2-Clause", "BSD 2-Clause", LicenseRisk.PERMISSIVE, True, True, False),
    "bsd-3-clause": LicenseInfo("BSD-3-Clause", "BSD 3-Clause", LicenseRisk.PERMISSIVE, True, True, False),
    "cc-by-4.0": LicenseInfo("CC-BY-4.0", "Creative Commons Attribution 4.0", LicenseRisk.PERMISSIVE, True, True, False),
    "cc-by-sa-4.0": LicenseInfo("CC-BY-SA-4.0", "CC Attribution ShareAlike 4.0", LicenseRisk.WEAK_COPYLEFT, True, True, True),
    "cc-by-nc-4.0": LicenseInfo("CC-BY-NC-4.0", "CC Attribution NonCommercial 4.0", LicenseRisk.RESTRICTIVE, False, True, False),
    "cc-by-nc-sa-4.0": LicenseInfo("CC-BY-NC-SA-4.0", "CC BY-NC-SA 4.0", LicenseRisk.RESTRICTIVE, False, True, True),
    "gpl-2.0": LicenseInfo("GPL-2.0", "GNU GPLv2", LicenseRisk.STRONG_COPYLEFT, True, True, True),
    "gpl-3.0": LicenseInfo("GPL-3.0", "GNU GPLv3", LicenseRisk.STRONG_COPYLEFT, True, True, True),
    "lgpl-2.1": LicenseInfo("LGPL-2.1", "GNU LGPLv2.1", LicenseRisk.WEAK_COPYLEFT, True, True, True),
    "lgpl-3.0": LicenseInfo("LGPL-3.0", "GNU LGPLv3", LicenseRisk.WEAK_COPYLEFT, True, True, True),
    "agpl-3.0": LicenseInfo("AGPL-3.0", "GNU AGPLv3", LicenseRisk.STRONG_COPYLEFT, True, True, True),
    "openrail": LicenseInfo("OpenRAIL", "Open RAIL License", LicenseRisk.RESTRICTIVE, True, True, False),
    "openrail++": LicenseInfo("OpenRAIL++", "Open RAIL++ License", LicenseRisk.RESTRICTIVE, True, True, False),
    "llama2": LicenseInfo("Llama-2", "Meta Llama 2 Community License", LicenseRisk.RESTRICTIVE, True, True, False),
    "llama3": LicenseInfo("Llama-3", "Meta Llama 3 Community License", LicenseRisk.RESTRICTIVE, True, True, False),
    "gemma": LicenseInfo("Gemma", "Google Gemma Terms of Use", LicenseRisk.RESTRICTIVE, True, True, False),
}


def normalize_license(raw: str) -> str:
    """Normalize a license string to our lookup key."""
    return re.sub(r"[\s_]+", "-", raw.strip().lower()).rstrip("-")


def lookup(license_str: str) -> Optional[LicenseInfo]:
    """Look up a license by its string identifier."""
    key = normalize_license(license_str)
    return _LICENSE_DB.get(key)


def check_license(
    license_str: Optional[str],
    require_commercial: bool = False,
    block_copyleft: bool = False,
    target: str = "",
) -> list[Finding]:
    """Check a model's license and return findings for policy violations.

    Args:
        license_str: The license identifier (SPDX or common name).
        require_commercial: If True, flag licenses that prohibit commercial use.
        block_copyleft: If True, flag copyleft licenses.
        target: File/model path for the finding.
    """
    findings: list[Finding] = []

    if not license_str or license_str.strip().lower() in ("", "unknown", "other", "none"):
        findings.append(Finding.artifact(
            rule_id="LICENSE-001",
            title="Missing or unknown model license",
            description="Model has no license metadata. Usage rights are unclear.",
            severity=Severity.MEDIUM,
            target=target,
        ))
        return findings

    info = lookup(license_str)
    if info is None:
        findings.append(Finding.artifact(
            rule_id="LICENSE-002",
            title=f"Unrecognized license: {license_str}",
            description="License not in known database. Manual review required.",
            severity=Severity.LOW,
            target=target,
            evidence=license_str,
        ))
        return findings

    if require_commercial and not info.commercial_ok:
        findings.append(Finding.artifact(
            rule_id="LICENSE-003",
            title=f"Non-commercial license: {info.name}",
            description=f"License {info.spdx_id} prohibits commercial use.",
            severity=Severity.HIGH,
            target=target,
            evidence=info.spdx_id,
        ))

    if block_copyleft and info.risk in (LicenseRisk.STRONG_COPYLEFT, LicenseRisk.WEAK_COPYLEFT):
        findings.append(Finding.artifact(
            rule_id="LICENSE-004",
            title=f"Copyleft license: {info.name}",
            description=f"License {info.spdx_id} requires derivative works to use the same license.",
            severity=Severity.MEDIUM,
            target=target,
            evidence=info.spdx_id,
        ))

    if info.risk == LicenseRisk.RESTRICTIVE:
        findings.append(Finding.artifact(
            rule_id="LICENSE-005",
            title=f"Restrictive license: {info.name}",
            description=f"License {info.spdx_id} has usage restrictions. Review terms before deployment.",
            severity=Severity.LOW,
            target=target,
            evidence=info.spdx_id,
        ))

    return findings
