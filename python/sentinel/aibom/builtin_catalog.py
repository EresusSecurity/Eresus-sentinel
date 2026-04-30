"""Builtin AI asset catalog — hardcoded entries for common models and tools."""
from __future__ import annotations

from sentinel.aibom.catalog_db import CatalogDB

_BUILTIN_ENTRIES = [
    {"name": "gpt-4", "vendor": "OpenAI", "license": "proprietary", "category": "llm"},
    {"name": "gpt-4o", "vendor": "OpenAI", "license": "proprietary", "category": "llm"},
    {"name": "gpt-3.5-turbo", "vendor": "OpenAI", "license": "proprietary", "category": "llm"},
    {"name": "claude-3-opus", "vendor": "Anthropic", "license": "proprietary", "category": "llm"},
    {"name": "claude-3-sonnet", "vendor": "Anthropic", "license": "proprietary", "category": "llm"},
    {"name": "claude-3-haiku", "vendor": "Anthropic", "license": "proprietary", "category": "llm"},
    {"name": "claude-4-sonnet", "vendor": "Anthropic", "license": "proprietary", "category": "llm"},
    {"name": "gemini-1.5-pro", "vendor": "Google", "license": "proprietary", "category": "llm"},
    {"name": "gemini-2.0-flash", "vendor": "Google", "license": "proprietary", "category": "llm"},
    {"name": "llama-3", "vendor": "Meta", "license": "Llama 3 Community License", "category": "llm"},
    {"name": "llama-3.1", "vendor": "Meta", "license": "Llama 3.1 Community License", "category": "llm"},
    {"name": "mistral-7b", "vendor": "Mistral AI", "license": "Apache-2.0", "category": "llm"},
    {"name": "mixtral-8x7b", "vendor": "Mistral AI", "license": "Apache-2.0", "category": "llm"},
    {"name": "bert-base-uncased", "vendor": "Google", "license": "Apache-2.0", "category": "embedding"},
    {"name": "text-embedding-ada-002", "vendor": "OpenAI", "license": "proprietary", "category": "embedding"},
    {"name": "text-embedding-3-small", "vendor": "OpenAI", "license": "proprietary", "category": "embedding"},
    {"name": "all-MiniLM-L6-v2", "vendor": "sentence-transformers", "license": "Apache-2.0", "category": "embedding"},
    {"name": "stable-diffusion-xl", "vendor": "Stability AI", "license": "CreativeML OpenRAIL-M", "category": "image"},
    {"name": "whisper-large-v3", "vendor": "OpenAI", "license": "MIT", "category": "audio"},
    {"name": "chromadb", "vendor": "Chroma", "license": "Apache-2.0", "category": "vector-store"},
    {"name": "pinecone", "vendor": "Pinecone", "license": "proprietary", "category": "vector-store"},
    {"name": "weaviate", "vendor": "Weaviate", "license": "BSD-3-Clause", "category": "vector-store"},
    {"name": "qdrant", "vendor": "Qdrant", "license": "Apache-2.0", "category": "vector-store"},
    {"name": "langchain", "vendor": "LangChain", "license": "MIT", "category": "agent-framework"},
    {"name": "langgraph", "vendor": "LangChain", "license": "MIT", "category": "agent-framework"},
    {"name": "crewai", "vendor": "CrewAI", "license": "MIT", "category": "agent-framework"},
]


def load_builtin_catalog(db: CatalogDB | None = None) -> CatalogDB:
    """Load the builtin catalog into a CatalogDB instance."""
    if db is None:
        db = CatalogDB()
    db.load_entries(_BUILTIN_ENTRIES)
    return db
