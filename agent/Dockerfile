# FlowStallion AI Agent (RCA sidecar) — Python 3, stdlib only, no external deps.
#
# Build:  docker build -f agent/Dockerfile -t flowstallion-ai:latest .
# Usage:  run via docker compose (service: ai-agent)

FROM python:3.13-slim

# git is required for on-demand PR-head checkouts (real-repo test selection).
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy only the package (not .venv / tests)
COPY agent/flowstallion_agent/ ./flowstallion_agent/

ENV PYTHONPATH=/app \
    PYTHONUNBUFFERED=1

CMD ["python", "-m", "flowstallion_agent"]
