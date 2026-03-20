SHELL := /bin/bash

# Default variables (override via environment)
ADDR ?= 127.0.0.1:8080
MEMPOOL_DIR ?= $(PWD)/pc-data/mempool
NETWORK_NAME ?= phantom-dev
SHARDS_INITIAL ?= 64
COMMITTEE_K ?= 21
TXS_PER_PAYLOAD ?= 256
FEATURES ?= 0

.PHONY: all check test e2e_genesis genesis_note node_status node_metrics

all: check

check:
	cargo check

test:
	cargo test

# Erzeugt genesis_note.bin im MEMPOOL_DIR
genesis_note:
	cargo run -p phantom-node --bin genesis_bootstrap -- \
		--mempool-dir "$(MEMPOOL_DIR)" \
		--network-name "$(NETWORK_NAME)" \
		--shards-initial "$(SHARDS_INITIAL)" \
		--committee-k "$(COMMITTEE_K)" \
		--txs-per-payload "$(TXS_PER_PAYLOAD)" \
		--features "$(FEATURES)"

# End-to-End Genesis Bootstrap Flow
# 1) genesis_note.bin erzeugen
# 2) status-serve starten und /readyz abwarten
# 3) /genesis/bootstrap ausführen
# 4) /status und /metrics prüfen
# Hinweis: nutzt das Script unter crates/phantom-node/scripts/e2e_genesis.sh
e2e_genesis:
	ADDR="$(ADDR)" MEMPOOL_DIR="$(MEMPOOL_DIR)" NETWORK_NAME="$(NETWORK_NAME)" \
	SHARDS_INITIAL="$(SHARDS_INITIAL)" COMMITTEE_K="$(COMMITTEE_K)" \
	TXS_PER_PAYLOAD="$(TXS_PER_PAYLOAD)" FEATURES="$(FEATURES)" \
	bash crates/phantom-node/scripts/e2e_genesis.sh

node_status:
	curl -s http://$(ADDR)/status | jq .

node_metrics:
	curl -s http://$(ADDR)/metrics | grep -E 'pc_network_id|pc_genesis_height' || true

# ------------------------------------------------------------
# GitHub Actions Utilities
# ------------------------------------------------------------

GH_OWNER ?= Global-Phantom-Network
GH_REPO  ?= Phantom-Coin
N        ?= 10

.PHONY: gh-runs-list gh-run-detail gh-run-rerun gh-dispatch-i9 tag

# Listet die letzten N Workflow-Runs
gh-runs-list:
	@set -euo pipefail; \
	url="https://api.github.com/repos/$(GH_OWNER)/$(GH_REPO)/actions/runs?per_page=$(N)"; \
	if [ -n "$${GH_TOKEN:-}" ]; then \
	  curl -s -H "Authorization: Bearer $$GH_TOKEN" -H "Accept: application/vnd.github+json" "$$url"; \
	else \
	  curl -s -H "Accept: application/vnd.github+json" "$$url"; \
	fi | jq -r '.workflow_runs[] | "id=\(.id) name=\(.name) event=\(.event) branch=\(.head_branch) status=\(.status) conclusion=\(.conclusion) created=\(.created_at)"'

# Zeigt Details (Jobs/fehlende Steps) eines Runs
# Nutzung: make gh-run-detail RUN_ID=19204693974
gh-run-detail:
	@test -n "$$RUN_ID" || { echo "Usage: make gh-run-detail RUN_ID=<id>"; exit 2; };
	@set -euo pipefail; \
	base="https://api.github.com/repos/$(GH_OWNER)/$(GH_REPO)/actions/runs/$$RUN_ID"; \
	if [ -n "$${GH_TOKEN:-}" ]; then \
	  run=$$(curl -s -H "Authorization: Bearer $$GH_TOKEN" -H "Accept: application/vnd.github+json" "$$base"); \
	  jobs=$$(curl -s -H "Authorization: Bearer $$GH_TOKEN" -H "Accept: application/vnd.github+json" "$$base/jobs?per_page=100"); \
	else \
	  run=$$(curl -s -H "Accept: application/vnd.github+json" "$$base"); \
	  jobs=$$(curl -s -H "Accept: application/vnd.github+json" "$$base/jobs?per_page=100"); \
	fi; \
	echo "--- run ---"; \
	echo "$$run" | jq -r '"workflow=\(.name) event=\(.event) branch=\(.head_branch) status=\(.status) conclusion=\(.conclusion) created=\(.created_at)"'; \
	echo "--- jobs ---"; \
	echo "$$jobs" | jq -r '.jobs[] | "job=\(.name) status=\(.status) conclusion=\(.conclusion)"'; \
	echo "--- failing steps ---"; \
	echo "$$jobs" | jq -r '.jobs[] | select(.conclusion!="success" and .conclusion!=null) | "job=\(.name)\n" + ( .steps | map(select(.conclusion!="success" and .conclusion!=null)) | map("  step=\(.name) conclusion=\(.conclusion)") | join("\n"))'

# Rerun eines spezifischen Runs (erfordert GH_TOKEN)
# Nutzung: make gh-run-rerun RUN_ID=19204693974
gh-run-rerun:
	@test -n "$$RUN_ID" || { echo "Usage: make gh-run-rerun RUN_ID=<id>"; exit 2; };
	@test -n "$$GH_TOKEN" || { echo "GH_TOKEN required (Personal Access Token mit repo-Rechten)"; exit 2; };
	@curl -s -X POST -H "Authorization: Bearer $$GH_TOKEN" -H "Accept: application/vnd.github+json" \
	  "https://api.github.com/repos/$(GH_OWNER)/$(GH_REPO)/actions/runs/$$RUN_ID/rerun" && echo "OK"

# Dispatch für den manuellen i9-Workflow (erfordert GH_TOKEN)
gh-dispatch-i9:
	@test -n "$$GH_TOKEN" || { echo "GH_TOKEN required (Personal Access Token mit repo-Rechten)"; exit 2; };
	@curl -s -X POST -H "Authorization: Bearer $$GH_TOKEN" -H "Accept: application/vnd.github+json" \
	  -d '{"ref":"main"}' \
	  "https://api.github.com/repos/$(GH_OWNER)/$(GH_REPO)/actions/workflows/benches-tp-i9-manual.yml/dispatches" && echo "OK"

# Hilfstarget zum Taggen und Pushen eines Releases
# Nutzung: make tag TAG=v0.0.2
tag:
	@test -n "$$TAG" || { echo "Usage: make tag TAG=vX.Y.Z"; exit 2; };
	@git tag -a "$$TAG" -m "release $$TAG" && git push origin "$$TAG"
