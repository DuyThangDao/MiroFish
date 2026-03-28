# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Is

MiroFish is a multi-agent swarm intelligence engine for predictive simulation. It orchestrates LLM-powered agents (via OASIS/CAMEL-AI) across simulated social platforms (Twitter/Reddit) to model how information spreads and predict outcomes. It uses Zep Cloud as a knowledge graph backend for entity memory and relationships.

## Commands

### Setup
```bash
cp .env.example .env          # fill in LLM_API_KEY and ZEP_API_KEY at minimum
npm run setup:all             # installs Node deps + creates Python venv + installs Python deps
```

### Development
```bash
npm run dev                   # starts both frontend (port 3000) and backend (port 5001) concurrently
npm run backend               # Flask only
npm run frontend              # Vite only
```

### Build & Docker
```bash
npm run build                 # builds frontend for production
docker compose up -d          # runs full stack in Docker
```

### Backend (Python) — run inside `backend/` with venv activated
```bash
source .venv/bin/activate
python run.py                 # starts Flask server directly
uv add <package>              # add a dependency (uses uv, not pip)
```

## Required Environment Variables

| Variable | Purpose |
|----------|---------|
| `LLM_API_KEY` | Primary LLM API key (OpenAI or compatible) |
| `ZEP_API_KEY` | Zep Cloud API key for knowledge graph |
| `LLM_BASE_URL` | Optional: custom endpoint for OpenAI-compatible APIs |
| `LLM_MODEL` | Optional: model name override |
| `BOOST_*` | Optional: second LLM config for expensive/long-running steps |

The app fails fast on startup if `LLM_API_KEY` or `ZEP_API_KEY` are missing.

## Architecture

### 5-Step Workflow Pipeline
1. **Graph Building** — Upload seed documents (PDF/TXT/MD) → extract ontology → build Zep knowledge graph
2. **Environment Setup** — Filter entities → generate OASIS agent profiles (personalities, behaviors)
3. **Simulation** — Run parallel multi-platform OASIS simulations as subprocess with IPC
4. **Report Generation** — ReportAgent (ReACT pattern) queries graph and generates analysis
5. **Interaction** — User interviews simulated agents; dialogue with ReportAgent

### Backend Structure (`backend/app/`)
- **`api/`** — Three Flask blueprints: `graph.py` (project/file management), `simulation.py` (agent profiles, sim control), `report.py` (reports, interviews)
- **`services/`** — Core logic; the heavy files are:
  - `simulation_runner.py` (1763 LOC) — manages OASIS subprocess, IPC, state machine
  - `report_agent.py` (2571 LOC) — multi-tool ReACT agent for report generation
  - `zep_tools.py` (1735 LOC) — tool suite wrapping Zep graph queries
  - `oasis_profile_generator.py` (1200 LOC) — generates agent social profiles
- **`models/`** — `Project` and `Task` dataclasses; state persisted as JSON in `backend/uploads/`
- **No database**: All persistence is file-based in `backend/uploads/`; Zep Cloud is the graph store

### Frontend Structure (`frontend/src/`)
- Vue 3 + Vite; Vite proxies `/api/*` to backend at port 5001
- **`views/`** — Page-level components mapped to routes
- **`api/`** — Axios-based API clients
- Routes: `/` → home, `/process/:projectId` → workflow, `/simulation/:simulationId/*` → sim setup/run, `/report/:reportId` → report, `/interaction/:reportId` → agent interview

### LLM Integration
- Uses the OpenAI SDK but works with any OpenAI-compatible endpoint (configured via `LLM_BASE_URL`)
- Reasoning models (e.g., MiniMax/GLM) may emit `<think>` tags and markdown code fences in the `content` field — the app strips these before parsing JSON responses (see recent fix in `985f89f`)

### Subprocess Simulation
OASIS simulations run as a separate subprocess to avoid Python GIL contention. Communication happens via IPC (pipes/queues). `atexit` hooks clean up processes on shutdown.

## Key Patterns

- **Task tracking**: Long-running operations create a `Task` object with progress state. Frontend polls the task endpoint.
- **File encoding**: Multi-fallback chain (UTF-8 → charset_normalizer → chardet → UTF-8 with replace).
- **Report tool calls**: ReportAgent validates tool call format strictly; malformed LLM outputs are retried.
- **JSON output**: Flask is configured with `JSON_ENSURE_ASCII=False` so Chinese characters render directly.
