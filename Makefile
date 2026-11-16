PYTHON ?= python3
PIP ?= $(PYTHON) -m pip
PYTEST ?= pytest
RUFF ?= ruff
BANDIT ?= bandit

.DEFAULT_GOAL := help
.PHONY: help install test coverage lint format format-check security check build clean scan rules

help:
	@echo "cloudrift development targets"
	@echo ""
	@echo "  make install       Install the package with development dependencies"
	@echo "  make test          Run the test suite"
	@echo "  make coverage      Run tests with a terminal coverage report"
	@echo "  make lint          Run ruff checks"
	@echo "  make format        Format the codebase with ruff"
	@echo "  make format-check  Verify formatting without changing files"
	@echo "  make security      Run bandit against src"
	@echo "  make check         Run lint, format-check, security, and tests"
	@echo "  make build         Build a wheel and source distribution"
	@echo "  make scan          Scan the vulnerable example"
	@echo "  make rules         List the bundled policies"
	@echo "  make clean         Remove caches and build artifacts"

install:
	$(PIP) install --upgrade pip
	$(PIP) install -e ".[dev]"

test:
	$(PYTEST)

coverage:
	$(PYTEST) --cov=cloudrift --cov-report=term-missing

lint:
	$(RUFF) check .

format:
	$(RUFF) format .

format-check:
	$(RUFF) format --check .

security:
	$(BANDIT) -r src

check: lint format-check security test

build:
	$(PYTHON) -m build

scan:
	$(PYTHON) -m cloudrift scan examples/vulnerable --no-color

rules:
	$(PYTHON) -m cloudrift rules list

clean:
	rm -rf build dist .pytest_cache .ruff_cache .coverage htmlcov
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	find . -type d -name "*.egg-info" -prune -exec rm -rf {} +
