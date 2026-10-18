.PHONY: all ci build lint unit codecheck test mutate fuzz prove parity correlate nearmiss tune red chain links score replay new clean

PY ?= python3
RASD = $(PY) rasd.py

all: ci

ci:              ## The full pipeline (the CI workflow adds ruff, mypy, script parse checks and the drift check)
	$(RASD) ci

build:           ## Queries, cards, views, coverage, scores, banner, red docs, chain outputs
	$(RASD) build

lint:            ## Rules, contracts, tuning guides, evidence files
	$(RASD) lint

unit:            ## Unit tests for the engine and every tool
	$(PY) -m unittest discover -s tests

codecheck:       ## Code checks of the tools: ruff (lint and security rules) and mypy
	ruff check .
	mypy

test:            ## Detection true-positive / true-negative tests
	$(RASD) test

mutate:          ## Technique and generic mutations
	$(RASD) mutate

fuzz:            ## Evasion fuzzer against the baseline
	$(RASD) fuzz --check

prove:           ## Rule mutation testing
	$(RASD) prove

parity:          ## Generated KQL / SPL behave like the rules
	$(RASD) parity

correlate:       ## Correlation proofs: scenarios, parameter mutants, aggregation parity, burst guarantee
	$(RASD) correlate -v

nearmiss:        ## Events one field edit away from an alert; correlation threshold headroom
	$(RASD) nearmiss

tune:            ## Tuning impact analysis
	$(RASD) tune --check

red:             ## Validate and render the offensive tests
	$(RASD) red

chain:           ## 20-point attack-to-defense map, maturity, matrices, metrics
	$(RASD) chain

links:           ## Every relative Markdown link resolves
	$(RASD) links

score:           ## Engineering and Operational Scores
	$(RASD) score

replay:          ## Replay the lab-day corpus
	$(RASD) replay samples/replay/lab-day.jsonl --assets samples/replay/assets.csv --users samples/replay/users.csv

new:             ## Scaffold a detection: make new ID=T1021.006 NAME=winrm_remote_shell
	$(RASD) new $(ID) $(NAME)

clean:
	rm -rf reports red/results __pycache__ tools/__pycache__ tests/__pycache__ red/web/__pycache__ samples/replay/__pycache__
