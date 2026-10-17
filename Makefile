.PHONY: demo up speel integratie test lint check down

COMPOSE := docker compose --progress quiet

.env:
	cp .env.example .env

## demo: start de keten schoon en speel de zes scenario's af (één commando)
demo: up speel

## up: start uitgever en inkomensregister vanuit een schone toestand
up: .env
	$(COMPOSE) down -v --remove-orphans
	$(COMPOSE) up -d --build --wait

## speel: speel de scenario's af tegen de draaiende keten
speel:
	@$(COMPOSE) run --rm demo

## integratie: alle integratietests tegen de echte keten
integratie: .env
	$(COMPOSE) down -v --remove-orphans
	$(COMPOSE) up -d --build --wait
	$(COMPOSE) run --rm tests

## test: unittests op de host
test:
	uv run --all-extras pytest -m "not integratie"

## lint: ruff, opmaak en typecontrole
lint:
	uv run ruff check .
	uv run ruff format --check .
	uv run ty check src tests

check: lint test integratie

down:
	$(COMPOSE) down -v --remove-orphans
