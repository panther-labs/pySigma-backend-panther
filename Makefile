.PHONY: help install dev test install-poetry lint format

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

install-poetry:
	@echo "Checking for poetry installation..."
	@if ! command -v poetry > /dev/null 2>&1; then \
		echo "Poetry not found, installing..."; \
		pip install poetry || python3 -m pip install poetry; \
	fi

install: install-poetry ## Install project dependencies
	@echo "Installing dependencies..."
	pip install poetry || python3 -m pip install poetry
	poetry install

dev: install-poetry ## Set up development environment
	@echo "Setting up development environment..."
	pip install poetry || python3 -m pip install poetry
	poetry install --with dev
	poetry run pip install -e .

test: install-poetry ## Run tests with coverage
	@echo "Running tests..."
	pip install poetry || python3 -m pip install poetry
	poetry run pytest tests/ --cov=sigma

lint: install-poetry ## Run linters (isort)
	@echo "Running linters..."
	pip install poetry || python3 -m pip install poetry
	poetry run isort --check-only sigma/ tests/

format: install-poetry ## Format code (black, isort)
	@echo "Formatting code..."
	pip install poetry || python3 -m pip install poetry
	poetry run black sigma/ tests/
	poetry run isort sigma/ tests/ 