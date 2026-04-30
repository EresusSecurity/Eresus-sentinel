"""Scan cloud provider configurations for AI/ML service usage."""
from __future__ import annotations

from pathlib import Path

from sentinel.aibom.models import AIComponent, AIComponentType
from sentinel.aibom.scanners.base import BaseAIBOMScanner

_AWS_AI_SERVICES = {
    "sagemaker": "AWS SageMaker",
    "bedrock": "AWS Bedrock",
    "comprehend": "AWS Comprehend",
    "rekognition": "AWS Rekognition",
    "textract": "AWS Textract",
    "transcribe": "AWS Transcribe",
    "polly": "AWS Polly",
    "lex": "AWS Lex",
    "kendra": "AWS Kendra",
}

_AZURE_AI_SERVICES = {
    "cognitiveservices": "Azure Cognitive Services",
    "openai.azure.com": "Azure OpenAI",
    "machinelearning": "Azure ML",
    "cognitive.microsoft.com": "Azure AI",
}

_GCP_AI_SERVICES = {
    "aiplatform": "Vertex AI",
    "ml.googleapis.com": "Google ML",
    "generativelanguage": "Gemini API",
    "vision.googleapis.com": "Cloud Vision",
    "speech.googleapis.com": "Cloud Speech",
    "language.googleapis.com": "Cloud NLP",
}

_ALL_SERVICES = {**_AWS_AI_SERVICES, **_AZURE_AI_SERVICES, **_GCP_AI_SERVICES}


class CloudScanner(BaseAIBOMScanner):
    name = "cloud-scanner"

    def scan(self, root: Path) -> list[AIComponent]:
        out: list[AIComponent] = []
        seen: set[str] = set()
        for p in self._iter_files(root, suffixes=(
            ".py", ".tf", ".yaml", ".yml", ".json", ".toml",
            ".js", ".ts", ".go", ".java",
        )):
            text = self._read(p)
            for key, label in _ALL_SERVICES.items():
                if key.lower() in text.lower():
                    dedup = f"{p}:{key}"
                    if dedup in seen:
                        continue
                    seen.add(dedup)
                    provider = "aws" if key in _AWS_AI_SERVICES else (
                        "azure" if key in _AZURE_AI_SERVICES else "gcp"
                    )
                    out.append(AIComponent(
                        type=AIComponentType.ENDPOINT,
                        name=f"cloud:{label}",
                        path=str(p),
                        description=f"Cloud AI service reference: {label}",
                        evidence=[f"{provider}-ai-service"],
                        properties={"provider": provider, "service": label, "keyword": key},
                    ))
        return out
