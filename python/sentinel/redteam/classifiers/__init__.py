"""
Eresus Sentinel — Red Team Response Classifiers.

Classifiers score model responses to determine if an attack succeeded
(i.e. the model complied with a harmful request).

Available classifiers:
  - HeuristicClassifier          — keyword/regex refusal detection (no API required)
  - CosineSimilarityClassifier   — semantic similarity vs. harmful reference corpus
  - SentimentClassifier          — positive sentiment as compliance signal
  - InsecureCodeScorer           — vulnerability detection in code responses
  - PlagiarismScorer             — training data memorization / n-gram overlap
  - LLMJudgeClassifier           — LLM-as-judge verdict (requires generator)
  - CommitteeClassifier          — ensemble voting from multiple classifiers
  - AWSBedrockClassifier         — Amazon Bedrock Guardrails API
  - AzureContentSafetyClassifier — Azure Content Safety API
"""

from sentinel.redteam.classifiers.base import ClassifierResult, ClassifierScore, ResponseClassifier
from sentinel.redteam.classifiers.cosine import CosineSimilarityClassifier
from sentinel.redteam.classifiers.heuristic import HeuristicClassifier, retry_with_backoff
from sentinel.redteam.classifiers.insecure_code import InsecureCodeScorer
from sentinel.redteam.classifiers.llm_judge import LLMJudgeClassifier
from sentinel.redteam.classifiers.plagiarism import PlagiarismScorer
from sentinel.redteam.classifiers.sentiment import SentimentClassifier
from sentinel.redteam.classifiers.committee import CommitteeClassifier

__all__ = [
    "ClassifierResult",
    "ClassifierScore",
    "ResponseClassifier",
    "HeuristicClassifier",
    "retry_with_backoff",
    "CosineSimilarityClassifier",
    "SentimentClassifier",
    "InsecureCodeScorer",
    "PlagiarismScorer",
    "LLMJudgeClassifier",
    "CommitteeClassifier",
]

try:
    from sentinel.redteam.classifiers.aws_bedrock import AWSBedrockClassifier
    __all__.append("AWSBedrockClassifier")
except ImportError:
    pass

try:
    from sentinel.redteam.classifiers.azure_content_safety import AzureContentSafetyClassifier
    __all__.append("AzureContentSafetyClassifier")
except ImportError:
    pass
