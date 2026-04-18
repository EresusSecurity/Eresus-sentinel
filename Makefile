# ============================================================================
# Eresus Sentinel — Makefile
# Production-grade AI/LLM Security Platform
# ============================================================================
# Usage:
#   make help           — Show all targets
#   make install        — Install with all dependencies
#   make dev            — Install dev environment
#   make lint           — Run all linters
#   make test           — Run test suite
#   make docker-build   — Build Docker image
#   make serve          — Start API server
# ============================================================================

.DEFAULT_GOAL := help

# ── Config ───────────────────────────────────────────────────────────
PYTHON      ?= python3
PIP         ?= $(PYTHON) -m pip
PYTEST      ?= $(PYTHON) -m pytest
RUFF        ?= $(PYTHON) -m ruff
MYPY        ?= $(PYTHON) -m mypy
UVICORN     ?= $(PYTHON) -m uvicorn

PKG_NAME    := eresus-sentinel
PKG_VERSION := $(shell $(PYTHON) -c "import sentinel; print(sentinel.__version__)" 2>/dev/null || echo "0.5.0")
DOCKER_TAG  := eresus/sentinel:$(PKG_VERSION)
DOCKER_LATEST := eresus/sentinel:latest

API_HOST    ?= 0.0.0.0
API_PORT    ?= 8080
API_WORKERS ?= 4

COV_MIN     ?= 60
SRC_DIR     := python/sentinel
TEST_DIR    := tests

# ── Colors ───────────────────────────────────────────────────────────
BLUE   := \033[36m
GREEN  := \033[32m
YELLOW := \033[33m
RED    := \033[31m
RESET  := \033[0m
BOLD   := \033[1m

# ============================================================================
# Installation
# ============================================================================

.PHONY: install
install: ## Install package with core dependencies
	@echo "$(BLUE)▸ Installing $(PKG_NAME)...$(RESET)"
	@$(PIP) install -e "." --quiet
	@echo "$(GREEN)✓ Installed successfully$(RESET)"

.PHONY: install-all
install-all: ## Install with ALL optional dependencies (ml, firewall, api, vault, hf, otel)
	@echo "$(BLUE)▸ Installing $(PKG_NAME) with all extras...$(RESET)"
	@$(PIP) install -e ".[all,otel]" --quiet
	@echo "$(GREEN)✓ Installed with all extras$(RESET)"

.PHONY: install-api
install-api: ## Install with API server dependencies
	@echo "$(BLUE)▸ Installing $(PKG_NAME) with API deps...$(RESET)"
	@$(PIP) install -e ".[api,otel]" --quiet
	@echo "$(GREEN)✓ API dependencies installed$(RESET)"

.PHONY: install-ml
install-ml: ## Install with ML model scanning dependencies (torch, transformers, onnx)
	@echo "$(BLUE)▸ Installing $(PKG_NAME) with ML deps...$(RESET)"
	@$(PIP) install -e ".[ml]" --quiet
	@echo "$(GREEN)✓ ML dependencies installed$(RESET)"

.PHONY: dev
dev: ## Install development environment (dev + all + pre-commit hooks)
	@echo "$(BLUE)▸ Setting up development environment...$(RESET)"
	@$(PIP) install -e ".[dev,all,otel,docs]" --quiet
	@pre-commit install 2>/dev/null || echo "$(YELLOW)⚠ pre-commit not found, skipping hooks$(RESET)"
	@echo "$(GREEN)✓ Development environment ready$(RESET)"

# ============================================================================
# Code Quality
# ============================================================================

.PHONY: lint
lint: ## Run all linters (ruff check + ruff format check)
	@echo "$(BLUE)▸ Running linters...$(RESET)"
	@$(RUFF) check $(SRC_DIR)
	@$(RUFF) format --check $(SRC_DIR)
	@echo "$(GREEN)✓ Lint passed$(RESET)"

.PHONY: lint-fix
lint-fix: ## Auto-fix lint issues
	@echo "$(BLUE)▸ Auto-fixing lint issues...$(RESET)"
	@$(RUFF) check --fix $(SRC_DIR)
	@$(RUFF) format $(SRC_DIR)
	@echo "$(GREEN)✓ Lint fixes applied$(RESET)"

.PHONY: typecheck
typecheck: ## Run mypy type checking
	@echo "$(BLUE)▸ Running type checker...$(RESET)"
	@$(MYPY) $(SRC_DIR) --ignore-missing-imports --no-error-summary
	@echo "$(GREEN)✓ Type check passed$(RESET)"

.PHONY: pre-commit
pre-commit: ## Run pre-commit hooks on all files
	@echo "$(BLUE)▸ Running pre-commit hooks...$(RESET)"
	@pre-commit run --all-files
	@echo "$(GREEN)✓ Pre-commit passed$(RESET)"

.PHONY: check
check: lint typecheck ## Run all quality checks (lint + typecheck)
	@echo "$(GREEN)✓ All quality checks passed$(RESET)"

# ============================================================================
# Testing
# ============================================================================

.PHONY: test
test: ## Run test suite
	@echo "$(BLUE)▸ Running tests...$(RESET)"
	@$(PYTEST) $(TEST_DIR) -v --tb=short
	@echo "$(GREEN)✓ Tests passed$(RESET)"

.PHONY: test-fast
test-fast: ## Run tests, stop on first failure
	@echo "$(BLUE)▸ Running tests (fail-fast)...$(RESET)"
	@$(PYTEST) $(TEST_DIR) -x -v --tb=short

.PHONY: test-cov
test-cov: ## Run tests with coverage report
	@echo "$(BLUE)▸ Running tests with coverage...$(RESET)"
	@$(PYTEST) $(TEST_DIR) -v \
		--cov=$(SRC_DIR) \
		--cov-report=term-missing \
		--cov-report=html:htmlcov \
		--cov-fail-under=$(COV_MIN)
	@echo "$(GREEN)✓ Coverage report: htmlcov/index.html$(RESET)"

.PHONY: test-unit
test-unit: ## Run only unit tests (exclude slow/integration)
	@$(PYTEST) $(TEST_DIR) -v -m "not slow and not integration" --tb=short

.PHONY: test-integration
test-integration: ## Run integration tests only
	@$(PYTEST) $(TEST_DIR) -v -m integration --tb=short

# ============================================================================
# Security Scanning
# ============================================================================

.PHONY: security-audit
security-audit: ## Run security audit on dependencies
	@echo "$(BLUE)▸ Auditing dependencies...$(RESET)"
	@$(PIP) audit 2>/dev/null || echo "$(YELLOW)⚠ pip-audit not installed: pip install pip-audit$(RESET)"

.PHONY: scan-self
scan-self: ## Run Sentinel on its own codebase (eat your own dog food)
	@echo "$(BLUE)▸ Self-scanning with Sentinel...$(RESET)"
	@$(PYTHON) -m sentinel.cli scan $(SRC_DIR) --format table 2>/dev/null || echo "$(YELLOW)⚠ CLI not available$(RESET)"

.PHONY: validate-rules
validate-rules: ## Validate all YAML rule files
	@echo "$(BLUE)▸ Validating rules...$(RESET)"
	@$(PYTHON) -c "from sentinel.cli_dispatch import dispatch_validate_rules; dispatch_validate_rules()" 2>/dev/null && echo "$(GREEN)✓ Rules valid$(RESET)" || echo "$(YELLOW)⚠ Validation module not callable directly$(RESET)"

# ============================================================================
# API Server
# ============================================================================

.PHONY: serve
serve: ## Start API server (development mode, auto-reload)
	@echo "$(BLUE)▸ Starting Sentinel API on $(API_HOST):$(API_PORT)...$(RESET)"
	@$(UVICORN) sentinel.server:create_app --factory \
		--host $(API_HOST) \
		--port $(API_PORT) \
		--reload \
		--reload-dir $(SRC_DIR)

.PHONY: serve-prod
serve-prod: ## Start API server (production mode, multiple workers)
	@echo "$(BLUE)▸ Starting Sentinel API (production) on $(API_HOST):$(API_PORT) with $(API_WORKERS) workers...$(RESET)"
	@$(UVICORN) sentinel.server:create_app --factory \
		--host $(API_HOST) \
		--port $(API_PORT) \
		--workers $(API_WORKERS) \
		--log-level warning

# ============================================================================
# Docker
# ============================================================================

.PHONY: docker-build
docker-build: ## Build Docker image
	@echo "$(BLUE)▸ Building Docker image $(DOCKER_TAG)...$(RESET)"
	@docker build -t $(DOCKER_TAG) -t $(DOCKER_LATEST) .
	@echo "$(GREEN)✓ Image built: $(DOCKER_TAG)$(RESET)"

.PHONY: docker-build-cuda
docker-build-cuda: ## Build Docker image with CUDA support
	@echo "$(BLUE)▸ Building Docker image with CUDA...$(RESET)"
	@docker build -f Dockerfile.cuda -t $(DOCKER_TAG)-cuda .
	@echo "$(GREEN)✓ Image built: $(DOCKER_TAG)-cuda$(RESET)"

.PHONY: docker-run
docker-run: ## Run Docker container (API server)
	@echo "$(BLUE)▸ Running Sentinel API container on port $(API_PORT)...$(RESET)"
	@docker run -it --rm \
		-p $(API_PORT):8080 \
		-v $(PWD)/config:/app/config:ro \
		-v $(PWD)/rules:/app/rules:ro \
		-e SENTINEL_ENV=production \
		$(DOCKER_LATEST)

.PHONY: docker-compose-up
docker-compose-up: ## Start full stack with docker-compose (API + Prometheus)
	@echo "$(BLUE)▸ Starting full stack...$(RESET)"
	@docker compose up -d
	@echo "$(GREEN)✓ Stack running — API: http://localhost:$(API_PORT) | Prometheus: http://localhost:9090$(RESET)"

.PHONY: docker-compose-down
docker-compose-down: ## Stop docker-compose stack
	@docker compose down

.PHONY: docker-compose-logs
docker-compose-logs: ## Tail docker-compose logs
	@docker compose logs -f --tail=50

# ============================================================================
# Build & Publish
# ============================================================================

.PHONY: build
build: clean-build ## Build distribution packages (sdist + wheel)
	@echo "$(BLUE)▸ Building distribution packages...$(RESET)"
	@$(PIP) install --upgrade build --quiet
	@$(PYTHON) -m build
	@echo "$(GREEN)✓ Built packages in dist/$(RESET)"

.PHONY: publish-test
publish-test: build ## Publish to TestPyPI
	@echo "$(BLUE)▸ Publishing to TestPyPI...$(RESET)"
	@$(PYTHON) -m twine upload --repository testpypi dist/*

.PHONY: publish
publish: build ## Publish to PyPI
	@echo "$(YELLOW)▸ Publishing to PyPI (PRODUCTION)...$(RESET)"
	@$(PYTHON) -m twine check dist/*
	@$(PYTHON) -m twine upload dist/*
	@echo "$(GREEN)✓ Published $(PKG_NAME) v$(PKG_VERSION) to PyPI$(RESET)"

# ============================================================================
# Documentation
# ============================================================================

.PHONY: docs-serve
docs-serve: ## Serve documentation locally (MkDocs)
	@echo "$(BLUE)▸ Serving documentation on http://localhost:8085...$(RESET)"
	@mkdocs serve -a localhost:8085

.PHONY: docs-build
docs-build: ## Build documentation site
	@echo "$(BLUE)▸ Building documentation...$(RESET)"
	@mkdocs build
	@echo "$(GREEN)✓ Documentation built in site/$(RESET)"

# ============================================================================
# Utilities
# ============================================================================

.PHONY: version
version: ## Show current version
	@echo "$(PKG_NAME) v$(PKG_VERSION)"

.PHONY: scanners
scanners: ## List all available scanners
	@$(PYTHON) -c "\
from sentinel._plugins import list_all_plugins; \
import json; \
plugins = list_all_plugins(); \
print('Input scanners:', len(plugins.get('input',[])), '→', ', '.join(sorted(plugins.get('input',[])))); \
print('Output scanners:', len(plugins.get('output',[])), '→', ', '.join(sorted(plugins.get('output',[])))); \
print('Artifact scanners:', len(plugins.get('artifact',[])), '→', ', '.join(sorted(plugins.get('artifact',[])))); \
" 2>/dev/null || echo "$(YELLOW)⚠ Run 'make install' first$(RESET)"

.PHONY: info
info: ## Show project info and dependency status
	@echo "$(BOLD)Eresus Sentinel v$(PKG_VERSION)$(RESET)"
	@echo "Python: $$($(PYTHON) --version)"
	@echo "Platform: $$(uname -s) $$(uname -m)"
	@echo ""
	@echo "$(BOLD)Core Dependencies:$(RESET)"
	@$(PYTHON) -c "import rich; print('  rich:', rich.__version__)" 2>/dev/null || echo "  rich: NOT INSTALLED"
	@$(PYTHON) -c "import yaml; print('  pyyaml:', yaml.__version__)" 2>/dev/null || echo "  pyyaml: NOT INSTALLED"
	@echo ""
	@echo "$(BOLD)Optional Dependencies:$(RESET)"
	@$(PYTHON) -c "import torch; print('  torch:', torch.__version__)" 2>/dev/null || echo "  torch: not installed"
	@$(PYTHON) -c "import transformers; print('  transformers:', transformers.__version__)" 2>/dev/null || echo "  transformers: not installed"
	@$(PYTHON) -c "import fastapi; print('  fastapi:', fastapi.__version__)" 2>/dev/null || echo "  fastapi: not installed"
	@$(PYTHON) -c "import uvicorn; print('  uvicorn:', uvicorn.__version__)" 2>/dev/null || echo "  uvicorn: not installed"
	@$(PYTHON) -c "import huggingface_hub; print('  huggingface-hub:', huggingface_hub.__version__)" 2>/dev/null || echo "  huggingface-hub: not installed"

# ============================================================================
# Cleanup
# ============================================================================

.PHONY: clean
clean: clean-build clean-pyc clean-test ## Remove all build, test, coverage and Python artifacts

.PHONY: clean-build
clean-build: ## Remove build artifacts
	@rm -rf build/ dist/ .eggs/ *.egg-info python/*.egg-info
	@find . -name '*.egg-info' -exec rm -rf {} + 2>/dev/null || true
	@find . -name '*.egg' -delete 2>/dev/null || true

.PHONY: clean-pyc
clean-pyc: ## Remove Python file artifacts
	@find . -name '*.pyc' -delete 2>/dev/null || true
	@find . -name '*.pyo' -delete 2>/dev/null || true
	@find . -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true
	@find . -name '*~' -delete 2>/dev/null || true

.PHONY: clean-test
clean-test: ## Remove test and coverage artifacts
	@rm -rf .pytest_cache/ htmlcov/ .coverage .coverage.* .mypy_cache/

.PHONY: clean-docker
clean-docker: ## Remove Docker images
	@docker rmi $(DOCKER_TAG) $(DOCKER_LATEST) 2>/dev/null || true
	@echo "$(GREEN)✓ Docker images removed$(RESET)"

# ============================================================================
# Help
# ============================================================================

.PHONY: help
help: ## Show this help message
	@echo ""
	@echo "$(BOLD)Eresus Sentinel v$(PKG_VERSION) — Available Commands$(RESET)"
	@echo ""
	@grep --no-filename -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; { \
			printf "  $(BLUE)%-22s$(RESET) %s\n", $$1, $$2; \
		}' | sort
	@echo ""
