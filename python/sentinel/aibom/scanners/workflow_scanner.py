"""Detect ML workflow artifacts (DVC, MLflow, W&B, kedro, prefect)."""
from __future__ import annotations

from pathlib import Path

from sentinel.aibom.models import AIComponent, AIComponentType
from sentinel.aibom.scanners.base import BaseAIBOMScanner

_WORKFLOW_FILES = {
    "dvc.yaml", "mlflow.yml", "mlflow.yaml", "wandb.yaml", "prefect.yaml",
    "kedro.yml", "params.yaml", "zenml.yaml",
}


class WorkflowScanner(BaseAIBOMScanner):
    name = "workflow-scanner"

    def scan(self, root: Path) -> list[AIComponent]:
        out: list[AIComponent] = []
        for p in self._iter_files(root):
            if p.name in _WORKFLOW_FILES:
                out.append(AIComponent(
                    type=AIComponentType.WORKFLOW,
                    name=p.name,
                    path=str(p),
                    description="ML workflow definition",
                    evidence=[p.name],
                ))
        return out
