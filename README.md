# Darkweb Monitoring - Agentic AI

Production-ready starter for an agentic dark-web investigation product inspired by the attached Google Threat Intelligence workflow: scope noisy underground mentions, pivot by actor/technical/financial paths, generate detection content, and preserve analyst-grade reports.

## What It Does

- Converts raw dark-web intelligence or OCR output into a structured investigation report.
- Extracts domains, actor handles, cryptocurrency addresses, technologies, and web-shell tradecraft.
- Scores risk against the organization profile.
- Generates B374K, WSO, and generic PHP web-shell YARA rules.
- Runs a MiroFish-inspired swarm simulation of SOC, threat intel, detection engineering, and risk-owner personas.
- Stores investigations in SQLite.
- Offers optional Google Cloud Vision OCR for screenshots, scanned snippets, and image evidence.
- Ships with API, browser UI, Dockerfile, Compose, CI, and tests.

## Quick Start

```bash
cp .env.example .env
python3 -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
uvicorn darkweb_monitoring.main:app --reload --host 0.0.0.0 --port 8000
```

Open `http://localhost:8000`.

## Google Cloud Vision OCR

1. Create a Google Cloud service account with Vision API access.
2. Download the JSON key locally.
3. Set:

```bash
VISION_OCR_ENABLED=true
GOOGLE_APPLICATION_CREDENTIALS=/absolute/path/to/service-account.json
GOOGLE_CLOUD_PROJECT=your-project-id
```

Then call:

```bash
curl -F "file=@evidence.png" http://localhost:8000/api/vision/ocr
```

## API

```bash
curl -X POST http://localhost:8000/api/investigations \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Shell Sales Analysis",
    "focus": "technical",
    "organization_profile": "Enterprise with public PHP and cPanel assets.",
    "seed_text": "Telegram seller @shellbroker advertises PHP shells, cPanel, SMTP, .gov/.edu targets, base64, .htaccess, cron, B374K and WSO.",
    "generate_yara": true,
    "run_swarm_simulation": true
  }'
```

## Public Tooling Notes

MiroFish is referenced as an architectural inspiration for swarm-style scenario simulation. Its public GitHub project describes graph construction, persona generation, multi-agent simulation, report generation, and deep interaction. This repo implements a clean-room lightweight simulation layer and does not vendor MiroFish code.

## Safety Boundaries

This product is for defensive threat intelligence. It is designed to ingest sanctioned evidence, analyst-provided snippets, paid threat intelligence exports, internal telemetry, or approved source collections. It does not include exploit execution, credential theft, unauthorized access, or dark-web purchasing workflows.

## Development

```bash
make install
make test
make lint
```

## Deployment

```bash
cp .env.example .env
docker compose up --build
```

For production, place the app behind an identity-aware proxy, configure TLS, use a managed database, store Google credentials in a secrets manager, and connect the API to approved telemetry sources.

