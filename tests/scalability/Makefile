# Scalability framework entry points. Run from this directory or with -C.
#
#   make cluster-up                      kind + kwok + Prometheus
#   make run DUT=knp-nri PODS=20000 IDENTITIES=700 SCENARIO=mesh
#   make matrix                          identity sweep over the three KNP DUTs
#   make report RUNS="_artifacts/a _artifacts/b"   Markdown + JSON into reports/
#   make smoke                           tiny run + verify, what CI executes
#   make cluster-down

SHELL := /usr/bin/env bash
.DEFAULT_GOAL := help

DUT ?= knp
NODES ?= 100
PODS ?= 10000
IDENTITIES ?= 7
NAMESPACES ?= 1
RATE ?= 100
SCENARIO ?= mesh
CHURN_RATE ?= 20
CHURN_DURATION ?= 120s
STEADY ?= 60s
CONNRATE_DURATION ?= 30s
EXTRA ?=

# Matrix defaults; override on the command line, e.g. MATRIX_DUTS="knp knp-nri".
MATRIX_DUTS ?= knp knp-nri knp-nri-iptracker
MATRIX_IDENTITIES ?= 7 700 3500
MATRIX_SCENARIOS ?= gateway mesh

export NODES PODS IDENTITIES NAMESPACES RATE SCENARIO CHURN_RATE CHURN_DURATION STEADY CONNRATE_DURATION

# Smoke parameters: small enough for a 4-vCPU CI runner, large enough to
# exercise every phase.
SMOKE_RUN_ID ?= smoke-$(DUT)
SMOKE_ARGS ?= --nodes 5 --pods 100 --identities 10 --rate 50 --scenario mesh \
              --churn-rate 5 --churn-duration 15s --steady 10s
RUNS ?= $(wildcard _artifacts/*/params.json)

.PHONY: help cluster-up cluster-down cluster-status monitoring loadgen run matrix smoke verify report clean-artifacts lint

help:
	@sed -n '2,9p' $(MAKEFILE_LIST)

cluster-up:
	./cluster.sh up
	./monitoring/install.sh

cluster-down:
	./cluster.sh down

cluster-status:
	./cluster.sh status

monitoring:
	./monitoring/install.sh $(DUT)

loadgen:
	cd ../.. && go build -o tests/scalability/_artifacts/loadgen ./tests/scalability/loadgen

run:
	./run.sh --dut $(DUT) $(EXTRA)

# One run per (dut, scenario, identities) with PODS held fixed. Pods per
# identity therefore varies; use PODS and IDENTITIES together to hold it.
matrix:
	@set -e; for d in $(MATRIX_DUTS); do \
	  for s in $(MATRIX_SCENARIOS); do \
	    for i in $(MATRIX_IDENTITIES); do \
	      echo ">>> dut=$$d scenario=$$s identities=$$i pods=$(PODS)"; \
	      ./run.sh --dut $$d --scenario $$s --identities $$i --pods $(PODS) $(EXTRA); \
	    done; \
	  done; \
	done

clean-artifacts:
	rm -rf _artifacts

smoke:
	./run.sh --dut $(DUT) --run-id $(SMOKE_RUN_ID) $(SMOKE_ARGS) $(EXTRA)
	./verify.sh _artifacts/$(SMOKE_RUN_ID)
	./report.sh _artifacts/$(SMOKE_RUN_ID) --out _artifacts/$(SMOKE_RUN_ID)/report

verify:
	./verify.sh _artifacts/$(RUN_ID)

# RUNS may be run directories or their params.json paths.
report:
	./report.sh $(patsubst %/params.json,%,$(RUNS))

lint:
	# SC1091: sources are resolved at runtime relative to BASH_SOURCE.
	shellcheck -x -e SC1091 lib.sh cluster.sh collect.sh run.sh report.sh verify.sh monitoring/install.sh probes/probes.sh dut/knp-lib.sh dut/*/dut.sh
	cd ../.. && go vet ./tests/scalability/loadgen/
