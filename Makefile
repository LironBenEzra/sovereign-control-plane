PY := .venv/bin/python
SPACY_MODEL := en_core_web_md

.PHONY: help up down install dev lint format typecheck test check verify demo tamper-demo ui

help:
	@echo "make up           run everything in Docker (API + UI + Ollama) on http://localhost:8000"
	@echo "make down         stop the Docker stack"
	@echo "make install      create .venv and install the backend for local development"
	@echo "make dev          run the API locally with stub models (no Docker, no API key)"
	@echo "make check        lint + type-check + tests"
	@echo "make demo         send the sample requests to a running control plane"
	@echo "make verify       verify the audit log: chain, signatures, replay"
	@echo "make tamper-demo  edit a copy of the audit log and show the verifier catching it"

up:
	docker compose up --build

down:
	docker compose down

install:
	python3 -m venv .venv
	$(PY) -m pip install --quiet --upgrade pip
	$(PY) -m pip install --quiet -e ".[dev]"
	$(PY) -m spacy download $(SPACY_MODEL)

dev:
	SCP_SOVEREIGN_PROVIDER=stub $(PY) -m uvicorn control_plane.main:create_app --factory --port 8000

ui:
	cd ui && npm install && npm run build

lint:
	$(PY) -m ruff check .
	$(PY) -m ruff format --check .

format:
	$(PY) -m ruff check --fix .
	$(PY) -m ruff format .

typecheck:
	$(PY) -m pyright

test:
	$(PY) -m pytest

check: lint typecheck test

verify:
	$(PY) -m control_plane.audit.verify --data-dir data

demo:
	./scripts/demo.sh

tamper-demo:
	$(PY) scripts/tamper_demo.py --data-dir data
