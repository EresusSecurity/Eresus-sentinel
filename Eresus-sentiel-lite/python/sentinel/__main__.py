"""
Eresus Sentinel — Package entry point.

Allows running: python3 -m sentinel [command] [args]

Examples:
    python3 -m sentinel scan ./project/
    python3 -m sentinel firewall "test input"
    python3 -m sentinel version
"""
from sentinel.cli import main

if __name__ == "__main__":
    main()
