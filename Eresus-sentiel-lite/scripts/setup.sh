#!/usr/bin/env bash
# ============================================================================
# Eresus Sentinel — Quick Setup Script
# Creates a virtual environment and installs all dependencies.
#
# Usage:
#   bash scripts/setup.sh          # default: install with all extras
#   bash scripts/setup.sh --core   # minimal: core only
#   bash scripts/setup.sh --ml     # core + ML scanning deps
# ============================================================================

set -euo pipefail

BLUE='\033[36m'
GREEN='\033[32m'
YELLOW='\033[33m'
RED='\033[31m'
BOLD='\033[1m'
RESET='\033[0m'

VENV_DIR=".venv"
EXTRAS="all"

# Parse arguments
for arg in "$@"; do
    case "$arg" in
        --core)   EXTRAS="" ;;
        --ml)     EXTRAS="scan" ;;
        --all)    EXTRAS="all" ;;
        --help|-h)
            echo "Usage: bash scripts/setup.sh [--core|--ml|--all]"
            echo "  --core   Install core dependencies only"
            echo "  --ml     Install core + ML scanning dependencies"
            echo "  --all    Install all dependencies (default)"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown argument: $arg${RESET}"
            exit 1
            ;;
    esac
done

echo -e "${BOLD}Eresus Sentinel — Setup${RESET}\n"

# ── Step 1: Detect package manager (prefer uv) ──────────────────────
USE_UV=false
if command -v uv &>/dev/null; then
    UV_VER=$(uv --version 2>/dev/null | head -1)
    echo -e "${GREEN}✓${RESET} Found uv ($UV_VER) — using uv for fast installs"
    USE_UV=true
else
    echo -e "${YELLOW}!${RESET} uv not found — falling back to python venv + pip"
    echo -e "  ${BLUE}Tip:${RESET} Install uv for 10-100x faster installs: ${BOLD}curl -LsSf https://astral.sh/uv/install.sh | sh${RESET}"
fi

# ── Step 2: Create virtual environment ───────────────────────────────
if [ -d "$VENV_DIR" ]; then
    echo -e "${GREEN}✓${RESET} Virtual environment already exists at ${VENV_DIR}/"
else
    echo -e "${BLUE}▸${RESET} Creating virtual environment..."
    if $USE_UV; then
        uv venv "$VENV_DIR"
    else
        python3 -m venv "$VENV_DIR"
    fi
    echo -e "${GREEN}✓${RESET} Created ${VENV_DIR}/"
fi

# ── Step 3: Install ──────────────────────────────────────────────────
INSTALL_SPEC="."
if [ -n "$EXTRAS" ]; then
    INSTALL_SPEC=".[$EXTRAS]"
fi

echo -e "${BLUE}▸${RESET} Installing eresus-sentinel${EXTRAS:+ [$EXTRAS]}..."

if $USE_UV; then
    uv pip install --python "$VENV_DIR/bin/python" -e "$INSTALL_SPEC"
else
    # Activate venv for pip
    source "$VENV_DIR/bin/activate"
    pip install --upgrade pip --quiet
    pip install -e "$INSTALL_SPEC"
fi

echo -e "${GREEN}✓${RESET} Installation complete\n"

# ── Step 4: Verify ───────────────────────────────────────────────────
echo -e "${BLUE}▸${RESET} Running health check..."

if $USE_UV; then
    "$VENV_DIR/bin/python" -m sentinel.cli doctor
else
    python -m sentinel.cli doctor
fi

echo ""
echo -e "${GREEN}${BOLD}Setup complete!${RESET}"
echo -e "Activate the environment with:"
echo -e "  ${BOLD}source ${VENV_DIR}/bin/activate${RESET}"
echo ""
echo -e "Then run:"
echo -e "  ${BOLD}sentinel scan ./path/to/project${RESET}"
echo -e "  ${BOLD}sentinel doctor${RESET}"
echo -e "  ${BOLD}sentinel --help${RESET}"
