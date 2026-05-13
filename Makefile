.PHONY: install test test-unit test-integration lint format security-check clean

install:
	pip install -r requirements.txt -r requirements-dev.txt && pip install -e .

test:
	pytest tests/ -v --cov=deltadb --cov-report=term-missing

test-unit:
	pytest tests/ -v -m "not integration"

test-integration:
	pytest tests/ -v -m "integration"

lint:
	ruff check .

format:
	black .

security-check:
	bandit -r deltadb/ -ll && pip-audit

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + && rm -rf .pytest_cache .coverage dist *.egg-info
