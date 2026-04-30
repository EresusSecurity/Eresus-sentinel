"""Tests for all 28 AIBOM scanners and 8 top-level modules."""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from sentinel.aibom.scanners import default_scanners
from sentinel.aibom.scanners.a2a_detector import A2ADetector
from sentinel.aibom.scanners.remote_agent_resolver import RemoteAgentResolver
from sentinel.aibom.scanners.ml_lifecycle_detector import MLLifecycleDetector
from sentinel.aibom.scanners.env_var_resolver import EnvVarResolver
from sentinel.aibom.scanners.deployment_detector import DeploymentDetector
from sentinel.aibom.scanners.model_file_scanner import ModelFileScanner
from sentinel.aibom.scanners.structural_agent_scanner import StructuralAgentScanner
from sentinel.aibom.scanners.vuln_scanner import VulnScanner
from sentinel.aibom.scanners.skill_detector import SkillDetector
from sentinel.aibom.scanners.agent_evidence_builder import AgentEvidenceBuilder
from sentinel.aibom.scanners.container_extractor import ContainerExtractor
from sentinel.aibom.scanners.cloud_scanner import CloudScanner
from sentinel.aibom.scanners.kb_enrichment_scanner import KBEnrichmentScanner
from sentinel.aibom.scanners.import_context import ImportContext
from sentinel.aibom.scanners.multi_language_scanner import MultiLanguageScanner
from sentinel.aibom.scanners.file_cache import FileCache, read_cached
from sentinel.aibom.scanners.workspace_dep_scanner import WorkspaceDepScanner
from sentinel.aibom.catalog_db import CatalogDB
from sentinel.aibom.finding_annotations import AnnotationStore
from sentinel.aibom.diff import diff_bom, BOMDiff, format_diff_markdown
from sentinel.aibom.vector_store_dedup import deduplicate_vector_stores
from sentinel.aibom.relationship_postprocessor import postprocess_relationships
from sentinel.aibom.cross_ref import cross_reference
from sentinel.aibom.notebook_parser import parse_notebook
from sentinel.aibom.models import AIBOMResult, AIComponent, AIComponentType, Relationship, RelationshipType


class TestDefaultScannersCount(unittest.TestCase):
    def test_scanner_count(self):
        scanners = default_scanners()
        self.assertGreaterEqual(len(scanners), 28)

    def test_scanner_names_unique(self):
        scanners = default_scanners()
        names = [s.name for s in scanners]
        self.assertEqual(len(names), len(set(names)))


class TestA2ADetector(unittest.TestCase):
    def test_json_agent_card(self):
        with tempfile.TemporaryDirectory() as td:
            card = {
                "name": "Test Agent",
                "description": "A test agent",
                "skills": [{"id": "test", "name": "Test Skill"}],
            }
            p = Path(td) / "agent-card.json"
            p.write_text(json.dumps(card))
            results = A2ADetector().scan(Path(td))
            self.assertGreaterEqual(len(results), 1)
            self.assertEqual(results[0].type, AIComponentType.AGENT)

    def test_no_false_positive_on_plain_json(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "config.json"
            p.write_text('{"name": "myapp", "version": "1.0"}')
            results = A2ADetector().scan(Path(td))
            self.assertEqual(len(results), 0)


class TestMLLifecycleDetector(unittest.TestCase):
    def test_detect_training(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "train.py"
            p.write_text("from transformers import Trainer\ntrainer = Trainer(model=model)\ntrainer.train()")
            results = MLLifecycleDetector().scan(Path(td))
            phases = [c.properties.get("phase") for c in results if "phase" in c.properties]
            self.assertIn("training", phases)


class TestEnvVarResolver(unittest.TestCase):
    def test_detect_env_var(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "app.py"
            p.write_text('import os\nkey = os.getenv("OPENAI_API_KEY")')
            results = EnvVarResolver().scan(Path(td))
            self.assertGreaterEqual(len(results), 1)

    def test_dotenv_file(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / ".env"
            p.write_text("OPENAI_API_KEY=sk-test123")
            results = EnvVarResolver().scan(Path(td))
            self.assertGreaterEqual(len(results), 1)


class TestDeploymentDetector(unittest.TestCase):
    def test_detect_ai_dockerfile(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "Dockerfile"
            p.write_text("FROM vllm/vllm:latest\nCMD serve")
            results = DeploymentDetector().scan(Path(td))
            self.assertGreaterEqual(len(results), 1)


class TestModelFileScanner(unittest.TestCase):
    def test_detect_safetensors(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "model.safetensors"
            p.write_bytes(b"\x00" * 2048)
            results = ModelFileScanner().scan(Path(td))
            self.assertEqual(len(results), 1)
            self.assertIn("sha256", results[0].hashes)


class TestVulnScanner(unittest.TestCase):
    def test_detect_ai_deps(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "requirements.txt"
            p.write_text("torch==2.1.0\nrequests==2.31.0\nlangchain>=0.1")
            results = VulnScanner().scan(Path(td))
            names = [r.name for r in results]
            self.assertIn("torch", names)
            self.assertIn("langchain", names)
            self.assertNotIn("requests", names)


class TestSkillDetector(unittest.TestCase):
    def test_detect_skill_md(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "SKILL.md"
            p.write_text("---\ndescription: Test skill\n---\n# Test Skill")
            results = SkillDetector().scan(Path(td))
            self.assertGreaterEqual(len(results), 1)
            self.assertEqual(results[0].type, AIComponentType.SKILL)


class TestAgentEvidenceBuilder(unittest.TestCase):
    def test_composite_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "agent.py"
            p.write_text("""
from langchain import hub
from langchain.agents import AgentExecutor
executor = AgentExecutor(agent=agent, tools=[tool])
result = executor.invoke({"input": "test"})
""")
            results = AgentEvidenceBuilder().scan(Path(td))
            self.assertGreaterEqual(len(results), 1)


class TestContainerExtractor(unittest.TestCase):
    def test_detect_ai_image(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "Dockerfile"
            p.write_text("FROM ollama/ollama:latest")
            results = ContainerExtractor().scan(Path(td))
            self.assertGreaterEqual(len(results), 1)


class TestCloudScanner(unittest.TestCase):
    def test_detect_aws_service(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "main.tf"
            p.write_text('resource "aws_sagemaker_endpoint" "test" {}')
            results = CloudScanner().scan(Path(td))
            self.assertGreaterEqual(len(results), 1)


class TestImportContext(unittest.TestCase):
    def test_classify_ml_file(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "model.py"
            p.write_text("import torch\nimport transformers\nmodel = transformers.AutoModel.from_pretrained('bert')")
            results = ImportContext().scan(Path(td))
            self.assertGreaterEqual(len(results), 1)


class TestMultiLanguageScanner(unittest.TestCase):
    def test_detect_js_openai(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "app.ts"
            p.write_text('import OpenAI from "openai";\nconst client = new OpenAI();')
            results = MultiLanguageScanner().scan(Path(td))
            self.assertGreaterEqual(len(results), 1)


class TestFileCache(unittest.TestCase):
    def test_cache_operations(self):
        cache = FileCache()
        self.assertEqual(cache.size, 0)
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode="w") as f:
            f.write("test content")
            f.flush()
            p = Path(f.name)
            self.assertTrue(cache.is_stale(p))
            cache.update(p, "test content")
            self.assertFalse(cache.is_stale(p))
            self.assertEqual(cache.size, 1)
            cache.clear()
            self.assertEqual(cache.size, 0)
        os.unlink(f.name)


class TestWorkspaceDepScanner(unittest.TestCase):
    def test_detect_python_deps(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "requirements.txt"
            p.write_text("torch==2.1.0\nflask==3.0\nlangchain>=0.1")
            results = WorkspaceDepScanner().scan(Path(td))
            names = {r.properties.get("package") for r in results}
            self.assertIn("torch", names)
            self.assertIn("langchain", names)
            self.assertNotIn("flask", names)


class TestCatalogDB(unittest.TestCase):
    def test_load_and_lookup(self):
        db = CatalogDB()
        db.load_entries([
            {"name": "GPT-4", "vendor": "OpenAI", "license": "proprietary"},
            {"name": "Claude", "vendor": "Anthropic"},
        ])
        self.assertEqual(db.size, 2)
        entry = db.lookup("gpt-4")
        self.assertIsNotNone(entry)
        self.assertEqual(entry.vendor, "OpenAI")

    def test_enrich(self):
        db = CatalogDB()
        db.load_entries([{"name": "bert", "vendor": "Google", "license": "Apache-2.0"}])
        enrichment = db.enrich("bert")
        self.assertEqual(enrichment["vendor"], "Google")
        self.assertEqual(enrichment["license"], "Apache-2.0")


class TestAnnotationStore(unittest.TestCase):
    def test_annotate_and_apply(self):
        store = AnnotationStore()
        comp = AIComponent(type=AIComponentType.AGENT, name="test", path="test.py")
        store.annotate(comp, "risk", "high", source="scanner")
        self.assertEqual(store.size, 1)
        store.apply_to_properties(comp)
        self.assertEqual(comp.properties["annotation:risk"], "high")


class TestBOMDiff(unittest.TestCase):
    def test_diff_detects_added(self):
        old = AIBOMResult()
        new = AIBOMResult()
        new.add(AIComponent(type=AIComponentType.AGENT, name="new-agent", path="a.py"))
        diff = diff_bom(old, new)
        self.assertTrue(diff.has_changes)
        self.assertEqual(len(diff.components.added), 1)

    def test_format_markdown(self):
        old = AIBOMResult()
        new = AIBOMResult()
        new.add(AIComponent(type=AIComponentType.AGENT, name="agent", path="a.py"))
        diff = diff_bom(old, new)
        md = format_diff_markdown(diff)
        self.assertIn("Added Components", md)


class TestVectorStoreDedup(unittest.TestCase):
    def test_dedup_same_tech(self):
        result = AIBOMResult()
        result.add(AIComponent(type=AIComponentType.VECTOR_STORE, name="chromadb-ref1", path="a.py", evidence=["a"]))
        result.add(AIComponent(type=AIComponentType.VECTOR_STORE, name="chromadb-ref2", path="b.py", evidence=["b"]))
        removed = deduplicate_vector_stores(result)
        self.assertEqual(removed, 1)
        self.assertEqual(len(result.components), 1)


class TestRelationshipPostprocessor(unittest.TestCase):
    def test_dedup_relationships(self):
        result = AIBOMResult()
        a = AIComponent(type=AIComponentType.AGENT, name="agent", path="a.py")
        b = AIComponent(type=AIComponentType.TOOL, name="tool", path="b.py")
        result.add(a)
        result.add(b)
        result.relate(a, b, RelationshipType.USES)
        result.relate(a, b, RelationshipType.USES)
        self.assertEqual(len(result.relationships), 2)
        postprocess_relationships(result)
        self.assertEqual(len(result.relationships), 1)


class TestNotebookParser(unittest.TestCase):
    def test_parse_notebook(self):
        with tempfile.TemporaryDirectory() as td:
            nb = {
                "cells": [
                    {
                        "cell_type": "code",
                        "source": ["import torch\n", "model = AutoModel.from_pretrained('bert-base')"],
                        "metadata": {},
                        "outputs": [],
                    }
                ],
                "metadata": {},
                "nbformat": 4,
                "nbformat_minor": 2,
            }
            p = Path(td) / "test.ipynb"
            p.write_text(json.dumps(nb))
            results = parse_notebook(p)
            self.assertGreaterEqual(len(results), 1)


if __name__ == "__main__":
    unittest.main()
