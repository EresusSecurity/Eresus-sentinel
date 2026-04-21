"""
Eresus Sentinel CLI package.

Re-exports main() for backward compatibility with:
    - pyproject.toml entry point: sentinel.cli:main
    - __main__.py: from sentinel.cli import main
"""

from sentinel.cli.main import main

__all__ = ["main"]
