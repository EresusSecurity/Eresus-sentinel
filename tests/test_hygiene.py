"""Hygiene tests: no forbidden external-brand strings, no emoji in frontend source, no Turkish UI strings."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FRONTEND_SRC = ROOT / "frontend" / "src"
PYTHON_SRC = ROOT / "python"
TESTS_DIR = ROOT / "tests"
DOCS_DIR = ROOT / "docs"
EXAMPLES_DIR = ROOT / "examples"

_FORBIDDEN_BRANDS = [
    "promptfoo",
    "PromptFoo",
    "garak",
    "PyRIT",
    "pyrit",
    "LLMFuzzer",
    "llmfuzzer",
    "CyberSecEval",
    "cyberseceval",
    "elder-plinius",
    "elder_plinius",
    "L1B3RT4S",
    "DeepTeam",
    "deepteam",
]

_EMOJI_PATTERN = re.compile(
    r"[\U0001F300-\U0001FAFF"
    r"\U00002700-\U000027BF"
    r"\U0000FE00-\U0000FE0F"
    r"\U00002600-\U000026FF"
    r"\U00002B50-\U00002B55"
    r"\U0000231A-\U0000231B"
    r"\U000025AA-\U000025FE"
    r"\U00002614-\U00002615"
    r"\U00002648-\U00002653"
    r"\U0000267F"
    r"\U00002693"
    r"\U000026A1"
    r"\U000026AA-\U000026AB"
    r"\U000026BD-\U000026BE"
    r"\U000026C4-\U000026C5"
    r"\U000026CE"
    r"\U000026D4"
    r"\U000026EA"
    r"\U000026F2-\U000026F3"
    r"\U000026F5"
    r"\U000026FA"
    r"\U000026FD"
    r"\U00002702"
    r"\U00002705"
    r"\U00002708-\U0000270D"
    r"\U0000270F"
    r"\U00002712"
    r"\U00002714"
    r"\U00002716"
    r"\U0000271D"
    r"\U00002721"
    r"\U00002728"
    r"\U00002733-\U00002734"
    r"\U00002744"
    r"\U00002747"
    r"\U0000274C"
    r"\U0000274E"
    r"\U00002753-\U00002755"
    r"\U00002757"
    r"\U00002763-\U00002764"
    r"\U00002795-\U00002797"
    r"\U000027A1"
    r"\U000027B0"
    r"\U000027BF"
    r"]"
)

_TURKISH_UI_WORDS = [
    "Giriş",
    "Çıkış",
    "Ayarlar",
    "Kaydet",
    "Ekle",
    "Düzenle",
    "Güncelle",
    "Tarama",
    "Güvenlik",
    "Bulgu",
    "Yükle",
    "İndir",
]

_TURKISH_WORD_RE = re.compile(
    r"(?<![A-Za-z])" + "(" + "|".join(re.escape(w) for w in _TURKISH_UI_WORDS) + ")" + r"(?![A-Za-z])"
)


def _python_source_files() -> list[Path]:
    return [
        f for f in PYTHON_SRC.rglob("*.py")
        if "__pycache__" not in f.parts
    ]


def _frontend_source_files() -> list[Path]:
    return [
        f for f in FRONTEND_SRC.rglob("*")
        if f.suffix in {".ts", ".tsx", ".js", ".jsx"}
        and "node_modules" not in f.parts
    ]


def _doc_files() -> list[Path]:
    return list(DOCS_DIR.rglob("*.md")) + list(EXAMPLES_DIR.rglob("*"))


def test_no_forbidden_brand_strings_in_python_source():
    violations: list[str] = []
    for path in _python_source_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        for brand in _FORBIDDEN_BRANDS:
            if brand in text:
                for i, line in enumerate(text.splitlines(), 1):
                    if brand in line:
                        violations.append(f"{path.relative_to(ROOT)}:{i}: {brand!r}")
    assert not violations, "Forbidden brand strings in Python source:\n" + "\n".join(violations)


def test_no_forbidden_brand_strings_in_docs():
    violations: list[str] = []
    for path in _doc_files():
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for brand in _FORBIDDEN_BRANDS:
            if brand in text:
                for i, line in enumerate(text.splitlines(), 1):
                    if brand in line:
                        violations.append(f"{path.relative_to(ROOT)}:{i}: {brand!r}")
    assert not violations, "Forbidden brand strings in docs/examples:\n" + "\n".join(violations)


def test_no_forbidden_brand_strings_in_tests():
    violations: list[str] = []
    this_file = Path(__file__).resolve()
    for path in TESTS_DIR.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        if path.resolve() == this_file:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for brand in _FORBIDDEN_BRANDS:
            if brand in text:
                for i, line in enumerate(text.splitlines(), 1):
                    if brand in line:
                        violations.append(f"{path.relative_to(ROOT)}:{i}: {brand!r}")
    assert not violations, "Forbidden brand strings in tests:\n" + "\n".join(violations)


def test_no_emoji_in_frontend_source():
    violations: list[str] = []
    for path in _frontend_source_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        for i, line in enumerate(text.splitlines(), 1):
            if _EMOJI_PATTERN.search(line):
                violations.append(f"{path.relative_to(ROOT)}:{i}: {line.strip()[:120]}")
    assert not violations, "Emoji found in frontend source (use Lucide icons instead):\n" + "\n".join(violations)


def test_no_turkish_ui_strings_in_frontend_source():
    violations: list[str] = []
    for path in _frontend_source_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        for i, line in enumerate(text.splitlines(), 1):
            m = _TURKISH_WORD_RE.search(line)
            if m:
                violations.append(f"{path.relative_to(ROOT)}:{i}: {m.group()!r}")
    assert not violations, "Turkish UI strings in frontend source:\n" + "\n".join(violations)


def test_no_turkish_ui_strings_in_python_source():
    violations: list[str] = []
    for path in _python_source_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        for i, line in enumerate(text.splitlines(), 1):
            m = _TURKISH_WORD_RE.search(line)
            if m:
                violations.append(f"{path.relative_to(ROOT)}:{i}: {m.group()!r}")
    assert not violations, "Turkish UI strings in Python source:\n" + "\n".join(violations)


def test_harmbench_brand_not_in_probe_class_names():
    harmbench_file = PYTHON_SRC / "sentinel" / "redteam" / "probes" / "harmbench.py"
    text = harmbench_file.read_text(encoding="utf-8")
    class_names = re.findall(r"^class (\w+)", text, re.MULTILINE)
    for name in class_names:
        assert "HarmBench" not in name, (
            f"Class {name!r} in harmbench.py still uses external brand 'HarmBench'"
        )


def test_harmbench_brand_not_in_extra_probes_class_names():
    extra_file = PYTHON_SRC / "sentinel" / "redteam" / "probes" / "extra_probes.py"
    text = extra_file.read_text(encoding="utf-8")
    class_names = re.findall(r"^class (\w+)", text, re.MULTILINE)
    for name in class_names:
        assert "HarmBench" not in name, (
            f"Class {name!r} in extra_probes.py still uses external brand 'HarmBench'"
        )


def test_harmful_behavior_probes_are_exported():
    init_file = PYTHON_SRC / "sentinel" / "redteam" / "probes" / "__init__.py"
    text = init_file.read_text(encoding="utf-8")
    assert "HarmfulBehaviorStandardProbe" in text
    assert "HarmfulBehaviorContextualProbe" in text
    assert "HarmfulBehaviorCopyrightProbe" in text
    assert "HarmfulBehaviorProbe" in text


def test_cyberseceval_brand_not_in_probe_class_names():
    cs_file = PYTHON_SRC / "sentinel" / "redteam" / "probes" / "cyberseceval.py"
    text = cs_file.read_text(encoding="utf-8")
    class_names = re.findall(r"^class (\w+)", text, re.MULTILINE)
    for name in class_names:
        assert "CyberSecEval" not in name, (
            f"Class {name!r} in cyberseceval.py still uses external brand 'CyberSecEval'"
        )


def test_pliny_brand_not_in_probe_class_names():
    for filename in ("benchmark_probes.py", "extra_probes.py"):
        path = PYTHON_SRC / "sentinel" / "redteam" / "probes" / filename
        text = path.read_text(encoding="utf-8")
        class_names = re.findall(r"^class (\w+)", text, re.MULTILINE)
        for name in class_names:
            assert "Pliny" not in name, (
                f"Class {name!r} in {filename} still uses external brand 'Pliny'"
            )


def test_jailbreak_dataset_probe_is_exported():
    init_file = PYTHON_SRC / "sentinel" / "redteam" / "probes" / "__init__.py"
    text = init_file.read_text(encoding="utf-8")
    assert "JailbreakDatasetProbe" in text
    assert "JailbreakRoleplayProbe" in text


def test_codesec_probes_are_exported():
    init_file = PYTHON_SRC / "sentinel" / "redteam" / "probes" / "__init__.py"
    text = init_file.read_text(encoding="utf-8")
    for name in ("InsecureCodeGenProbe", "ExploitGenProbe", "SocialEngineeringProbe",
                 "MalwareConceptProbe", "NetworkAttackProbe"):
        assert name in text, f"{name!r} not found in probes __init__.py"


_AGENT_PROBE_NAMES = [
    "AgentIdentityAbuseProbe",
    "ToolMetadataPoisoningProbe",
    "InsecureInterAgentCommunicationProbe",
    "CrossContextRetrievalProbe",
    "SystemReconnaissanceProbe",
    "ExploitToolAgentProbe",
    "AutonomousAgentDriftProbe",
    "GoalTheftProbe",
    "RecursiveHijackingProbe",
    "CrescendoJailbreakProbe",
]


def test_agent_probes_are_exported():
    init_file = PYTHON_SRC / "sentinel" / "redteam" / "probes" / "__init__.py"
    text = init_file.read_text(encoding="utf-8")
    missing = [name for name in _AGENT_PROBE_NAMES if name not in text]
    assert not missing, (
        "Agent probes not exported from probes/__init__.py:\n" + "\n".join(missing)
    )


def test_all_extra_probes_completeness():
    import importlib
    import inspect

    extra_mod = importlib.import_module("sentinel.redteam.probes.extra_probes")
    from sentinel.redteam.probe import Probe

    defined_classes = {
        name
        for name, obj in inspect.getmembers(extra_mod, inspect.isclass)
        if issubclass(obj, Probe) and obj is not Probe and obj.__module__ == extra_mod.__name__
    }
    registered_classes = {type(p).__name__ for p in extra_mod.ALL_EXTRA_PROBES}
    missing = defined_classes - registered_classes
    assert not missing, (
        "Probe subclasses defined in extra_probes.py but absent from ALL_EXTRA_PROBES:\n"
        + "\n".join(sorted(missing))
    )


def test_all_agent_probes_completeness():
    import importlib
    import inspect

    agent_mod = importlib.import_module("sentinel.redteam.probes.agent_probes")
    from sentinel.redteam.probe import Probe

    defined_classes = {
        name
        for name, obj in inspect.getmembers(agent_mod, inspect.isclass)
        if issubclass(obj, Probe) and obj is not Probe and obj.__module__ == agent_mod.__name__
    }
    registered_classes = {type(p).__name__ for p in agent_mod.ALL_AGENT_PROBES}
    missing = defined_classes - registered_classes
    assert not missing, (
        "Probe subclasses defined in agent_probes.py but absent from ALL_AGENT_PROBES:\n"
        + "\n".join(sorted(missing))
    )


def test_no_shadow_imports_from_extra_probes():
    init_file = PYTHON_SRC / "sentinel" / "redteam" / "probes" / "__init__.py"
    text = init_file.read_text(encoding="utf-8")
    should_not_be_in_extra_block = [
        "ContextComplianceProbe",
        "ExcessiveAgencyProbe",
        "GoalMisalignmentProbe",
        "HijackingProbe",
        "IndirectPromptInjectionProbe",
        "IntentProbe",
        "ModelIdentificationProbe",
        "MultiInputFormatProbe",
        "RAGSourceAttributionProbe",
        "ToxicChatProbe",
        "UnsafeBenchProbe",
        "UnverifiableClaimsProbe",
        "WordplayProbe",
        "XSTestProbe",
    ]
    import_block_start = text.find("from sentinel.redteam.probes.extra_probes import")
    extra_block = text[import_block_start:import_block_start + 2000] if import_block_start != -1 else ""
    for name in should_not_be_in_extra_block:
        assert name not in extra_block, (
            f"{name!r} is imported from extra_probes — this shadows the canonical implementation."
        )

    should_not_be_in_agent_block = [
        "ExcessiveAgencyProbe",
        "GoalMisalignmentProbe",
        "HijackingProbe",
        "IntentProbe",
    ]
    agent_block_start = text.find("from sentinel.redteam.probes.agent_probes import")
    agent_block = text[agent_block_start:agent_block_start + 2000] if agent_block_start != -1 else ""
    for name in should_not_be_in_agent_block:
        assert name not in agent_block, (
            f"{name!r} is imported from agent_probes — this shadows the canonical implementation."
        )


def test_dataset_importer_exports_harmful_behavior_key():
    from sentinel.redteam.dataset_importer import DatasetImporter

    importer = DatasetImporter(prefer_offline=True)
    available = importer.available_datasets()
    assert "harmful_behavior" in available

    ds = importer.load_offline("harmful_behavior")
    assert ds.size > 0
    assert ds.source == "offline"
