# FlowStallion — build entrypoints
# Dual stack: Go kernel (cmd/, pkg/) + Python AI agent (agent/).
#
# Offline / air-gapped use:
#   PIP_EXTRA='--find-links ./wheels --no-index' make setup
#   (requires a local wheel cache containing setuptools, wheel, pip,
#    pytest, mypy and their dependencies)

GO        := go
VENV      := agent/.venv
PIP       := $(VENV)/bin/python -m pip
PIP_EXTRA ?=

.PHONY: setup build run test vet clean ci

setup:
	$(GO) mod download
	@if [ ! -d $(VENV) ]; then \
		echo ">> creating $(VENV)"; \
		python3 -m venv $(VENV); \
	else \
		echo ">> $(VENV) exists — skipping creation (idempotent)"; \
	fi
	@if ! $(VENV)/bin/python -m pip --version >/dev/null 2>&1; then \
		echo ">> pip missing in $(VENV), bootstrapping via ensurepip"; \
		$(VENV)/bin/python -m ensurepip --upgrade || \
			{ echo "ERROR: pip bootstrap failed in $(VENV)"; exit 1; }; \
	fi
	@if $(VENV)/bin/python -c "import socket; socket.setdefaulttimeout(3); socket.getaddrinfo('pypi.org',443)" >/dev/null 2>&1; then \
		$(PIP) install --upgrade pip; \
	else \
		echo ">> pypi.org unreachable — skipping pip self-upgrade (offline mode)"; \
	fi
	@echo ">> installing agent[dev]"
	@if $(PIP) install -e "agent[dev]" $(PIP_EXTRA); then \
		echo ">> installed agent[dev]"; \
	elif $(PIP) install -e "agent[dev]" --no-build-isolation $(PIP_EXTRA); then \
		echo ">> installed agent[dev] without build isolation (venv provides setuptools)"; \
	else \
		echo "ERROR: could not install agent[dev]." >&2; \
		echo "  Online:  fix network access or set PIP_INDEX_URL to a private mirror." >&2; \
		echo "  Offline: pre-seed the venv (pip install setuptools wheel pytest mypy)" >&2; \
		echo "            or use PIP_EXTRA='--find-links ./wheels --no-index' make setup" >&2; \
		exit 1; \
	fi

build:
	mkdir -p bin
	$(GO) build -o bin/flowstallion ./cmd/flowstallion
	$(GO) build -o bin/scheduler ./cmd/scheduler
	$(GO) build -o bin/agent ./cmd/agent

run: build
	./bin/scheduler

vet:
	$(GO) vet ./...

test:
	$(GO) build ./...
	$(GO) vet ./...
	$(GO) test ./...
	@if [ ! -x $(VENV)/bin/pytest ]; then \
		echo ">> $(VENV) missing — run 'make setup' first"; exit 1; \
	fi
	$(VENV)/bin/pytest agent/tests -q
	$(VENV)/bin/mypy --config-file agent/pyproject.toml agent/

clean:
	rm -rf bin

# One-shot full gate: format, build, vet, race tests (Go), pytest + mypy
# (Python agent), and bash syntax of ops scripts. Must exit 0 in a clean
# environment for a change to merge.
UNFORMATTED := $(shell gofmt -l cmd pkg 2>/dev/null)

ci:
	@if [ -n "$(UNFORMATTED)" ]; then \
		echo "ERROR: gofmt: files need formatting:"; \
		echo "$(UNFORMATTED)"; \
		exit 1; \
	fi
	@echo ">> ci: gofmt OK"
	@echo ">> ci: go build"
	$(GO) build ./...
	@echo ">> ci: go vet"
	$(GO) vet ./...
	@echo ">> ci: go test -race"
	$(GO) test -race -count=1 ./...
	@echo ">> ci: bash -n scripts/tunnel.sh"
	bash -n scripts/tunnel.sh
	@echo ">> ci: pytest"
	@if [ ! -x $(VENV)/bin/pytest ]; then \
		echo "ERROR: $(VENV)/bin/pytest missing — run 'make setup' first"; exit 1; \
	fi
	$(VENV)/bin/pytest agent/tests -q
	@echo ">> ci: mypy"
	$(VENV)/bin/mypy --config-file agent/pyproject.toml agent/
	@echo ">> ci: all green"
