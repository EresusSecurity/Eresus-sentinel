"""Eresus Sentinel CLI package."""


def main():
    """Lazy entry point wrapper for `sentinel.cli:main`."""
    from sentinel.cli.main import main as _main

    return _main()

__all__ = ["main"]
