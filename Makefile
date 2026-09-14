.DEFAULT_GOAL := help
IMAGE ?= preflight
TAG   ?= dev

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "};{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

install: ## Create the venv and install everything
	uv sync

fmt: ## Autofix and format
	uv run ruff check --fix .
	uv run ruff format .

lint: ## Lint (no fixes)
	uv run ruff check .
	uv run ruff format --check .

types: ## Typecheck
	uv run mypy

test: ## Run the test suite
	uv run pytest

cov: ## Test suite with coverage
	uv run pytest --cov=preflight --cov-report=term-missing

check: lint types test ## Everything CI runs

demo: ## Scan the deliberately vulnerable fixture app
	uv run preflight scan fixtures/vulnerable-app --json out/demo.json --html out/demo.html

serve: ## Run the API locally
	PREFLIGHT_ALLOWED_ROOTS=$(PWD)/fixtures uv run uvicorn preflight.service.app:app --reload

docker-build: ## Build the container image
	docker build -t $(IMAGE):$(TAG) .

docker-run: ## Run the container image
	docker run --rm -p 8000:8000 -e PREFLIGHT_ALLOWED_ROOTS=/scan -v $(PWD)/fixtures:/scan:ro $(IMAGE):$(TAG)

.PHONY: help install fmt lint types test cov check demo serve docker-build docker-run
