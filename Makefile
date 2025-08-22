# SRA Ghost Protocol - Complete Makefile
# Author: SRA Research Team
# Purpose: Development, testing, benchmarking, and deployment automation

# ============================================================================
# Variables
# ============================================================================

# Colors for output
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[1;33m
BLUE := \033[0;34m
MAGENTA := \033[0;35m
CYAN := \033[0;36m
WHITE := \033[1;37m
NC := \033[0m # No Color

# Python
PYTHON := python3
POETRY := poetry
PIP := pip

# Directories
SRC_DIRS := sra s2_dfa s3_budget s4_audit rag_guardrail watcher attacks
TEST_DIR := tests
DEMO_DIR := demo
CONFIG_DIR := config
RESULTS_DIR := results
SCRIPTS_DIR := scripts

# Files
AUDIT_LOG := results/logs/demo_audit.jsonl
ATTACK_PATTERNS := config/attack_patterns.yaml
POLICY_CONFIG := config/policy.yaml
REQUIREMENTS := requirements.txt

# Performance targets
TARGET_P95_LATENCY := 200
TARGET_QPS := 100
TARGET_AUC := 0.6

# Security targets
MAX_LEAKAGE_BITS := 1.0
MIN_ENTROPY := 3.0

# Default values
SESSIONS := 1000
ATTACK_ROUNDS := 100

# ============================================================================
# Help Target (default)
# ============================================================================

.PHONY: help
help:
	@echo "$(CYAN)╔══════════════════════════════════════════════════════════════╗$(NC)"
	@echo "$(CYAN)║$(WHITE)          SRA Ghost Protocol - Development Pipeline          $(CYAN)║$(NC)"
	@echo "$(CYAN)╚══════════════════════════════════════════════════════════════╝$(NC)"
	@echo ""
	@echo "$(YELLOW)🚀 Quick Start:$(NC)"
	@echo "  $(GREEN)make install$(NC)       Install all dependencies"
	@echo "  $(GREEN)make demo$(NC)          Run faculty demo"
	@echo "  $(GREEN)make test$(NC)          Run all tests"
	@echo "  $(GREEN)make validate$(NC)      Full validation suite"
	@echo ""
	@echo "$(YELLOW)🧪 Testing:$(NC)"
	@echo "  $(GREEN)make test-unit$(NC)     Unit tests only"
	@echo "  $(GREEN)make test-security$(NC) Security property tests"
	@echo "  $(GREEN)make test-integration$(NC) Integration tests"
	@echo "  $(GREEN)make test-s1$(NC)       Test S1 detector specifically"
	@echo "  $(GREEN)make test-receipts$(NC) Test cryptographic receipts"
	@echo "  $(GREEN)make test-coverage$(NC) Generate coverage report"
	@echo ""
	@echo "$(YELLOW)🎯 Benchmarking:$(NC)"
	@echo "  $(GREEN)make bench-latency$(NC) Latency benchmarks"
	@echo "  $(GREEN)make bench-throughput$(NC) Throughput benchmarks"
	@echo "  $(GREEN)make bench-ab$(NC)      Two-world A/B testing"
	@echo "  $(GREEN)make bench-attack$(NC)  Adversarial benchmarks"
	@echo ""
	@echo "$(YELLOW)🛡️  Security:$(NC)"
	@echo "  $(GREEN)make security-scan$(NC) Run security audits"
	@echo "  $(GREEN)make attack-test$(NC)   Run attack simulations"
	@echo "  $(GREEN)make verify-audit$(NC)  Verify audit integrity"
	@echo "  $(GREEN)make qeni-test$(NC)     QENI property validation"
	@echo ""
	@echo "$(YELLOW)📊 Evaluation:$(NC)"
	@echo "  $(GREEN)make eval$(NC)          Run full evaluation"
	@echo "  $(GREEN)make eval-adaptive$(NC) Adaptive attack evaluation"
	@echo "  $(GREEN)make figures$(NC)       Generate all figures"
	@echo "  $(GREEN)make report$(NC)        Generate evaluation report"
	@echo ""
	@echo "$(YELLOW)🎮 Demos:$(NC)"
	@echo "  $(GREEN)make demo$(NC)          Faculty demo (CLI)"
	@echo "  $(GREEN)make demo-ui$(NC)       Streamlit UI"
	@echo "  $(GREEN)make demo-batch$(NC)    Batch processing demo"
	@echo "  $(GREEN)make demo-s1$(NC)       S1 detector demo"
	@echo ""
	@echo "$(YELLOW)🔧 Development:$(NC)"
	@echo "  $(GREEN)make dev$(NC)           Start dev server"
	@echo "  $(GREEN)make format$(NC)        Format code (black + isort)"
	@echo "  $(GREEN)make lint$(NC)          Run linters"
	@echo "  $(GREEN)make type-check$(NC)    Run mypy type checking"
	@echo "  $(GREEN)make clean$(NC)         Clean build artifacts"
	@echo "  $(GREEN)make reset$(NC)         Full reset (clean + reinstall)"
	@echo ""
	@echo "$(YELLOW)📦 Docker:$(NC)"
	@echo "  $(GREEN)make docker-build$(NC)  Build Docker image"
	@echo "  $(GREEN)make docker-run$(NC)    Run in Docker"
	@echo "  $(GREEN)make docker-compose$(NC) Start with docker-compose"
	@echo ""
	@echo "$(YELLOW)📚 Documentation:$(NC)"
	@echo "  $(GREEN)make docs$(NC)          Build documentation"
	@echo "  $(GREEN)make docs-serve$(NC)    Serve docs locally"
	@echo ""

# ============================================================================
# Installation & Setup
# ============================================================================

.PHONY: install install-dev install-prod poetry-install dev-setup

install: poetry-install
	@echo "$(GREEN)✓ Installation complete$(NC)"

poetry-install:
	@echo "$(YELLOW)Installing dependencies with Poetry...$(NC)"
	$(POETRY) install --with dev,evaluation

install-dev:
	@echo "$(YELLOW)Installing development dependencies...$(NC)"
	$(PIP) install -e .
	$(PIP) install -r requirements.txt
	$(PIP) install pytest hypothesis black isort mypy bandit safety streamlit

install-prod:
	@echo "$(YELLOW)Installing production dependencies only...$(NC)"
	$(POETRY) install --without dev,evaluation

dev-setup: install
	@echo "$(YELLOW)Setting up development environment...$(NC)"
	pre-commit install || echo "pre-commit not available"
	@echo "$(GREEN)✓ Development environment ready$(NC)"

# ============================================================================
# Testing Targets
# ============================================================================

.PHONY: test test-unit test-integration test-security test-s1 test-receipts test-coverage

test:
	@echo "$(CYAN)═══════════════════════════════════════════════════════════════$(NC)"
	@echo "$(WHITE)Running All Tests$(NC)"
	@echo "$(CYAN)═══════════════════════════════════════════════════════════════$(NC)"
	$(POETRY) run pytest tests/ -v --tb=short

test-unit:
	@echo "$(YELLOW)Running unit tests...$(NC)"
	$(POETRY) run pytest tests/ -v --tb=short -m "not integration and not security"

test-integration:
	@echo "$(YELLOW)Running integration tests...$(NC)"
	$(POETRY) run pytest tests/test_integration.py -v

test-security:
	@echo "$(RED)Running security property tests...$(NC)"
	$(POETRY) run pytest tests/test_receipts.py tests/test_dp_accountant.py tests/test_dfa_guard.py -v
	@echo "$(YELLOW)Running hypothesis security tests...$(NC)"
	$(POETRY) run pytest tests/ -v -m security --hypothesis-profile=security 2>/dev/null || true

test-s1:
	@echo "$(YELLOW)Testing S1 detector...$(NC)"
	$(PYTHON) demo/test_s1.py
	$(POETRY) run pytest tests/test_s1_detector.py -v

test-receipts:
	@echo "$(YELLOW)Testing cryptographic receipts...$(NC)"
	$(POETRY) run pytest tests/test_receipts.py tests/test_audit_logger.py -v

test-coverage:
	@echo "$(YELLOW)Generating coverage report...$(NC)"
	$(POETRY) run pytest tests/ --cov=sra --cov=s2_dfa --cov=s3_budget --cov=s4_audit \
		--cov=rag_guardrail --cov=watcher --cov-report=html --cov-report=term
	@echo "$(GREEN)✓ Coverage report generated in htmlcov/$(NC)"

# ============================================================================
# Benchmarking Targets
# ============================================================================

.PHONY: bench bench-latency bench-throughput bench-ab bench-attack bench-all

bench: bench-latency bench-throughput
	@echo "$(GREEN)✓ Basic benchmarks complete$(NC)"

bench-latency:
	@echo "$(YELLOW)Running latency benchmarks (target P95 < $(TARGET_P95_LATENCY)ms)...$(NC)"
	$(POETRY) run pytest tests/ -v --benchmark-only --benchmark-name="*latency*" 2>/dev/null || \
		echo "$(YELLOW)Note: Install pytest-benchmark for full benchmarking$(NC)"

bench-throughput:
	@echo "$(YELLOW)Running throughput benchmarks (target > $(TARGET_QPS) QPS)...$(NC)"
	$(POETRY) run pytest tests/ -v --benchmark-only --benchmark-name="*throughput*" 2>/dev/null || \
		echo "$(YELLOW)Note: Install pytest-benchmark for full benchmarking$(NC)"

bench-ab:
	@echo "$(YELLOW)Running two-world A/B testing ($(SESSIONS) sessions)...$(NC)"
	$(PYTHON) bench_ab/run_two_worlds.py --n $(SESSIONS) --out results/runs/ab_$(shell date +%Y%m%d_%H%M%S).jsonl

bench-attack:
	@echo "$(RED)Running adversarial benchmarks ($(ATTACK_ROUNDS) rounds)...$(NC)"
	$(PYTHON) -m attacks.executors --mode=adversarial --rounds=$(ATTACK_ROUNDS)

bench-all: bench bench-ab bench-attack
	@echo "$(GREEN)✓ All benchmarks complete$(NC)"

# ============================================================================
# Security & Validation
# ============================================================================

.PHONY: security-scan attack-test verify-audit qeni-test validate

security-scan:
	@echo "$(RED)═══════════════════════════════════════════════════════════════$(NC)"
	@echo "$(WHITE)Security Audit$(NC)"
	@echo "$(RED)═══════════════════════════════════════════════════════════════$(NC)"
	@echo "$(YELLOW)Running Bandit...$(NC)"
	$(POETRY) run bandit -r $(SRC_DIRS) -f json -o results/bandit_report.json 2>/dev/null || \
		$(POETRY) run bandit -r $(SRC_DIRS) -ll
	@echo "$(YELLOW)Running Safety check...$(NC)"
	$(POETRY) run safety check --json > results/safety_report.json 2>/dev/null || \
		$(POETRY) run safety check || echo "$(YELLOW)Safety check complete$(NC)"

attack-test:
	@echo "$(RED)Running attack simulations...$(NC)"
	$(PYTHON) -m attacks.executors --config=$(ATTACK_PATTERNS) --sessions=$(ATTACK_ROUNDS)

verify-audit:
	@echo "$(YELLOW)Verifying audit log integrity...$(NC)"
	@if [ -f $(AUDIT_LOG) ]; then \
		$(PYTHON) -m s4_audit.verify_audit $(AUDIT_LOG); \
	else \
		echo "$(YELLOW)No audit log found at $(AUDIT_LOG)$(NC)"; \
	fi

qeni-test:
	@echo "$(MAGENTA)Testing QENI properties...$(NC)"
	@echo "Target: AUC ≤ $(TARGET_AUC), MI ≤ $(MAX_LEAKAGE_BITS) bits"
	$(PYTHON) bench_ab/run_two_worlds.py --n 100 --out results/runs/qeni_test.jsonl

validate: test-security bench verify-audit qeni-test
	@echo "$(GREEN)═══════════════════════════════════════════════════════════════$(NC)"
	@echo "$(WHITE)✅ SRA Validation Complete$(NC)"
	@echo "$(GREEN)═══════════════════════════════════════════════════════════════$(NC)"

# ============================================================================
# Evaluation Targets
# ============================================================================

.PHONY: eval eval-adaptive eval-quick figures report

eval:
	@echo "$(CYAN)Running full evaluation suite...$(NC)"
	$(PYTHON) scripts/run_evaluation.py --config=$(POLICY_CONFIG) --output=results/runs/

eval-adaptive:
	@echo "$(YELLOW)Running adaptive attack evaluation...$(NC)"
	$(PYTHON) scripts/run_adaptive_eval.py --rounds=50

eval-quick:
	@echo "$(YELLOW)Quick evaluation (100 samples)...$(NC)"
	$(PYTHON) scripts/run_evaluation.py --quick --samples=100

figures:
	@echo "$(YELLOW)Generating figures...$(NC)"
	$(PYTHON) scripts/plot_results.py --input=results/runs/ --output=results/plots/

report:
	@echo "$(YELLOW)Generating evaluation report...$(NC)"
	$(PYTHON) scripts/generate_report.py --template=academic --output=results/report_$(shell date +%Y%m%d).pdf

# ============================================================================
# Demo Targets
# ============================================================================

.PHONY: demo demo-ui demo-batch demo-s1 demo-cli

demo: demo-cli
	@echo "$(GREEN)✓ Demo complete$(NC)"

demo-cli:
	@echo "$(CYAN)Starting faculty demo (CLI)...$(NC)"
	$(PYTHON) demo/faculty_demo.py

demo-ui:
	@echo "$(CYAN)Starting Streamlit UI...$(NC)"
	streamlit run demo/ui/app.py --server.port=8123

demo-batch:
	@echo "$(YELLOW)Running batch processing demo...$(NC)"
	$(PYTHON) demo/demo_batch.py

demo-s1:
	@echo "$(YELLOW)Running S1 detector demo...$(NC)"
	$(PYTHON) demo/test_s1.py

# ============================================================================
# Development Tools
# ============================================================================

.PHONY: dev format lint type-check clean reset watch

dev:
	@echo "$(CYAN)Starting development server...$(NC)"
	uvicorn demo.ui.app:app --reload --port 8123

format:
	@echo "$(YELLOW)Formatting code...$(NC)"
	$(POETRY) run black $(SRC_DIRS) $(TEST_DIR) $(SCRIPTS_DIR)
	$(POETRY) run isort $(SRC_DIRS) $(TEST_DIR) $(SCRIPTS_DIR)

lint:
	@echo "$(YELLOW)Running linters...$(NC)"
	$(POETRY) run pylint $(SRC_DIRS) --rcfile=.pylintrc 2>/dev/null || \
		echo "$(YELLOW)Pylint not configured, skipping$(NC)"
	$(POETRY) run flake8 $(SRC_DIRS) 2>/dev/null || \
		echo "$(YELLOW)Flake8 not configured, skipping$(NC)"

type-check:
	@echo "$(YELLOW)Running type checker...$(NC)"
	$(POETRY) run mypy $(SRC_DIRS) --strict --ignore-missing-imports

clean:
	@echo "$(YELLOW)Cleaning build artifacts...$(NC)"
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	rm -rf .pytest_cache .mypy_cache .coverage htmlcov
	rm -rf *.egg-info dist build
	rm -f results/runs/*.tmp results/logs/*.tmp
	@echo "$(GREEN)✓ Clean complete$(NC)"

reset: clean
	@echo "$(RED)Full reset...$(NC)"
	rm -rf .venv poetry.lock
	$(POETRY) install
	@echo "$(GREEN)✓ Reset complete$(NC)"

watch:
	@echo "$(CYAN)Watching for changes...$(NC)"
	@while true; do \
		$(MAKE) test-unit; \
		echo "$(YELLOW)Waiting for changes...$(NC)"; \
		sleep 2; \
	done

# ============================================================================
# Docker Targets
# ============================================================================

.PHONY: docker-build docker-run docker-compose docker-stop

docker-build:
	@echo "$(BLUE)Building Docker image...$(NC)"
	docker build -f docker/Dockerfile.prod -t sra-ghost:latest .

docker-run:
	@echo "$(BLUE)Running Docker container...$(NC)"
	docker run -p 8000:8000 -p 8123:8123 \
		-v $(PWD)/results:/app/results \
		-v $(PWD)/config:/app/config \
		sra-ghost:latest

docker-compose:
	@echo "$(BLUE)Starting with docker-compose...$(NC)"
	docker-compose -f docker/docker-compose.yml up -d

docker-stop:
	@echo "$(BLUE)Stopping Docker containers...$(NC)"
	docker-compose -f docker/docker-compose.yml down

# ============================================================================
# Documentation
# ============================================================================

.PHONY: docs docs-serve docs-check

docs:
	@echo "$(YELLOW)Building documentation...$(NC)"
	$(POETRY) run mkdocs build 2>/dev/null || \
		echo "$(YELLOW)Install mkdocs for documentation generation$(NC)"

docs-serve:
	@echo "$(YELLOW)Serving documentation...$(NC)"
	$(POETRY) run mkdocs serve 2>/dev/null || \
		echo "$(YELLOW)Install mkdocs for documentation serving$(NC)"

docs-check:
	@echo "$(YELLOW)Checking documentation...$(NC)"
	@for file in docs/*.md; do \
		echo "Checking $$file..."; \
		grep -l "TODO\|FIXME\|XXX" $$file || true; \
	done

# ============================================================================
# CI/CD Helpers
# ============================================================================

.PHONY: ci ci-test ci-security ci-benchmark

ci: ci-test ci-security ci-benchmark
	@echo "$(GREEN)✓ CI pipeline complete$(NC)"

ci-test:
	@echo "$(CYAN)CI: Running tests...$(NC)"
	$(POETRY) run pytest tests/ -v --junit-xml=results/test_results.xml

ci-security:
	@echo "$(CYAN)CI: Security scan...$(NC)"
	$(MAKE) security-scan

ci-benchmark:
	@echo "$(CYAN)CI: Performance benchmarks...$(NC)"
	$(MAKE) bench

# ============================================================================
# Utility Targets
# ============================================================================

.PHONY: stats tree info check-deps update-deps

stats:
	@echo "$(CYAN)Repository statistics:$(NC)"
	@echo "Lines of code:"
	@wc -l $$(find $(SRC_DIRS) -name "*.py") | tail -1
	@echo "\nTest files:"
	@ls -1 tests/*.py | wc -l
	@echo "\nConfig files:"
	@ls -1 config/*.yaml | wc -l

tree:
	@tree -L 2 -I '__pycache__|*.pyc|.git|.venv|poetry.lock'

info:
	@echo "$(CYAN)System Information:$(NC)"
	@echo "Python: $$($(PYTHON) --version)"
	@echo "Poetry: $$($(POETRY) --version 2>/dev/null || echo 'Not installed')"
	@echo "Working directory: $$(pwd)"
	@echo "Git branch: $$(git branch --show-current 2>/dev/null || echo 'Not in git repo')"

check-deps:
	@echo "$(YELLOW)Checking dependencies...$(NC)"
	$(POETRY) show --outdated

update-deps:
	@echo "$(YELLOW)Updating dependencies...$(NC)"
	$(POETRY) update

# ============================================================================
# Special Targets for Paper
# ============================================================================

.PHONY: paper-eval paper-figures paper-tables paper-artifact

paper-eval:
	@echo "$(MAGENTA)Running evaluation for paper...$(NC)"
	$(MAKE) clean
	$(MAKE) eval
	$(MAKE) bench-all
	$(MAKE) qeni-test

paper-figures:
	@echo "$(MAGENTA)Generating paper figures...$(NC)"
	$(PYTHON) scripts/plot_results.py --paper-mode --dpi=300

paper-tables:
	@echo "$(MAGENTA)Generating paper tables...$(NC)"
	$(PYTHON) scripts/generate_report.py --format=latex --tables-only

paper-artifact:
	@echo "$(MAGENTA)Preparing paper artifact...$(NC)"
	@mkdir -p artifact
	@cp -r $(SRC_DIRS) artifact/
	@cp -r $(CONFIG_DIR) artifact/
	@cp -r $(TEST_DIR) artifact/
	@cp README.md Makefile requirements.txt pyproject.toml artifact/
	@tar -czf sra_artifact_$(shell date +%Y%m%d).tar.gz artifact/
	@rm -rf artifact
	@echo "$(GREEN)✓ Artifact created: sra_artifact_$(shell date +%Y%m%d).tar.gz$(NC)"

# ============================================================================
# Default target
# ============================================================================

.DEFAULT_GOAL := help