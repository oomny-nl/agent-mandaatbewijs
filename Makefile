.PHONY: demo up speel opname integratie test lint check down

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

## opname: neem de demo op met VHS (demo/demo.tape) en maak er een gif van voor de README
## vhs stopt niet bij een falende demo: eerst een gewone run die bij afwijking faalt, dan
## een schone keten zodat de bewijstabel in de opname alleen de opgenomen run toont
opname: up
	@$(COMPOSE) run --rm demo > /dev/null
	$(MAKE) up
	vhs demo/demo.tape
	timeout 600 ffmpeg -nostdin -y -loglevel error -i demo/demo.mp4 \
		-vf "fps=6,scale=1100:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=24:stats_mode=diff[p];[b][p]paletteuse=dither=none:diff_mode=rectangle" \
		docs/beeld/demo.gif

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
