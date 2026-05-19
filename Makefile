.PHONY: install dev test lint

install:
	python3 -m venv .venv
	. .venv/bin/activate && pip install -e ".[dev]"

dev:
	. .venv/bin/activate && uvicorn darkweb_monitoring.main:app --reload --host 0.0.0.0 --port 8000

test:
	. .venv/bin/activate && pytest -q

lint:
	. .venv/bin/activate && ruff check .

