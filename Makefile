.PHONY: install test validate init-db benchmark-check lint

install:
	python -m pip install -e ".[dev]"

test:
	python -m pytest -q

validate:
	python scripts/validate_obligations.py

init-db:
	python scripts/init_db.py

benchmark-check:
	python scripts/check_scenarios.py

lint:
	python -m ruff check src tests scripts
