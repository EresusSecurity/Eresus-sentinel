"""Allow ``python -m sentinel.cli`` to behave like the installed CLI."""

from sentinel.cli.main import main

if __name__ == "__main__":
    main()
