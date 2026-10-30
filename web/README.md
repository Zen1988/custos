# Custos HTML5 + Python (Flask) UI prototype

## Run locally
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```
Open http://127.0.0.1:8080

This is **not** a production application. It has mock data and NO login, API calls, database tables, authorization, console bridge, snapshot processing, audit storage or security hardening. Do not expose this demo publicly.

## Suggested production persistence
- SQLite for a single process, local demo or prototype only.
- PostgreSQL for Kubernetes multi-replica operation, concurrent writes, audit history and durable task state.
- Do not use the SQLite DB file on a shared multi-writer PVC.

Production implementation still needs OIDC authentication, resource authorization, CSRF safeguards, rate limits, gateway separation, secure secrets, task persistence and vendor adapter version validation.
