.PHONY: install test test-unit test-integration lint format security-check clean \
        setup-secrets docker-up docker-down docker-logs docker-test

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

setup-secrets:
	@echo "Generating random passwords in secrets/"
	@mkdir -p secrets
	@# [SECURITY] Generate cryptographically strong random passwords via Python secrets module
	@test -f secrets/pg_password.txt && echo "secrets/pg_password.txt already exists" || python -c "import secrets; open('secrets/pg_password.txt','w').write(secrets.token_urlsafe(32))"
	@test -f secrets/mysql_password.txt && echo "secrets/mysql_password.txt already exists" || python -c "import secrets; open('secrets/mysql_password.txt','w').write(secrets.token_urlsafe(32))"
	@test -f secrets/mysql_root_password.txt && echo "secrets/mysql_root_password.txt already exists" || python -c "import secrets; open('secrets/mysql_root_password.txt','w').write(secrets.token_urlsafe(32))"
	@echo "Done. Passwords in secrets/*.txt — NEVER commit these files."

docker-up:
	docker-compose up -d --wait

docker-down:
	docker-compose down -v

docker-logs:
	docker-compose logs -f

docker-test:
	make docker-up && pytest tests/ -v -m "integration" && make docker-down
