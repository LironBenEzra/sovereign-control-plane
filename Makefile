PY := .venv/bin/python
SPACY_MODEL := en_core_web_md

.PHONY: help up down install dev lint format typecheck test check verify demo tamper-demo eval-semantic ui

help:
	@echo "make up           run everything in Docker (API + UI + Ollama) on http://localhost:8000"
	@echo "make down         stop the Docker stack"
	@echo "make install      create .venv and install the backend for local development"
	@echo "make dev          run the API locally with stub models (no Docker, no API key)"
	@echo "make check        lint + type-check + tests"
	@echo "make demo         send the sample requests to a running control plane"
	@echo "make verify       verify the audit log: chain, signatures, replay"
	@echo "make tamper-demo  edit a copy of the audit log and show the verifier catching it"
	@echo "make eval-semantic measure the semantic detector on a labelled set, with the real model"
	@echo "                  (verify, tamper-demo and eval-semantic run inside the container;"
	@echo "                   add LOCAL=1 to run them on this machine after 'make dev')"

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

# The audit log lives in a Docker volume, so by default these run inside the container.
# LOCAL=1 runs them against ./data instead, for use with `make dev`.
ifdef LOCAL
RUN := $(PY)
DATA := data
else
RUN := docker compose exec control-plane python
DATA := /app/data
endif

verify:
	$(RUN) -m control_plane.audit.verify --data-dir $(DATA)

tamper-demo:
	$(RUN) scripts/tamper_demo.py --data-dir $(DATA)

eval-semantic:
	$(RUN) scripts/eval_semantic.py

demo:
	python3 scripts/demo.py
