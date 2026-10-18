.PHONY: demo up speel opname integratie test lint check down

COMPOSE := docker compose --progress quiet

.env:
	cp .env.example .env

## demo: start de keten schoon en speel de zes scenario's af (één commando)
## Eerst `up`, dan pas `speel`: ook met `make -j` start de demo niet tegen een halve keten
demo: up
	@$(MAKE) --no-print-directory speel

## up: start uitgever en inkomensregister vanuit een schone toestand
## `down -v` wist eerst de volumes: sleutels, wachtwoorden, registerdata en auditlogs
up: .env
	$(COMPOSE) down -v --remove-orphans
	$(COMPOSE) up -d --build --wait

## speel: speel de scenario's af tegen de draaiende keten
speel:
	@$(COMPOSE) run --rm demo

## opname: neem de demo op met VHS (demo/demo.tape) en maak er een gif van voor de README
## vereist vhs en ffmpeg op de host
## vhs stopt niet bij een falende demo: eerst een gewone run die bij afwijking faalt, dan
## een schone keten zodat de bewijstabel in de opname alleen de opgenomen run toont
opname: up
	@$(COMPOSE) run --rm demo > /dev/null
	$(MAKE) up
	vhs demo/demo.tape
	ffmpeg -nostdin -y -loglevel error -i demo/demo.mp4 \
		-vf "fps=6,scale=1100:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=24:stats_mode=diff[p];[b][p]paletteuse=dither=none:diff_mode=rectangle" \
		docs/beeld/demo.gif

## integratie: alle integratietests tegen de echte keten (wist de volumes, zoals `up`)
integratie: .env
	$(COMPOSE) down -v --remove-orphans
	$(COMPOSE) up -d --build --wait
	$(COMPOSE) run --rm tests

## test: unittests op de host (vereist uv)
test:
	uv run --all-extras pytest -m "not integratie"

## lint: ruff, opmaak en typecontrole, met dezelfde extra's als CI (vereist uv)
lint:
	uv run --all-extras ruff check .
	uv run --all-extras ruff format --check .
	uv run --all-extras ty check src tests

check: lint test integratie

## down: stop de keten en wis de volumes (sleutels, wachtwoorden, registerdata, auditlogs)
down:
	$(COMPOSE) down -v --remove-orphans
