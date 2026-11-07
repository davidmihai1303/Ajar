.PHONY: up down test analyze-validation agent gitleaks

up:
	docker compose up -d --build

down:
	docker compose down

test:
	docker compose run --rm app pytest -q

analyze-validation:
	docker compose run --rm app netcheck analyze /app/tests/fixtures/validation --out /data/input/validation_results

agent:
	python3 scanner/agent.py serve

gitleaks:
	gitleaks detect --source . --no-banner
