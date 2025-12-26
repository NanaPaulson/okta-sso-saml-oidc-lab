# Django Okta SSO Lab

A Django 6.0 lab that demonstrates Okta SSO via OIDC and SAML, plus Google OAuth as an extra IdP. Includes a SOC-themed dashboard showing recent security events and which IdP was used. Deploy-ready on Render.

## Features
- Okta OIDC authorization-code flow (`/oidc/login` → `/oidc/callback`)
- Okta SAML redirect/ACS flow (`/saml/login` → `/saml/acs`) with `/saml/debug/` to verify config
- Google OAuth 2.0 with optional domain allowlist (`GOOGLE_ALLOWED_DOMAIN`)
- SOC dashboard (`/soc/`) with recent events, severity/protocol counts, and simple trend buckets
- Env-driven Postgres or SQLite; Procfile for gunicorn deployment (used by Render)

## Stack
- Django 6.0
- requests, python-dotenv
- gunicorn (deployment)
- Optional: psycopg2-binary for Postgres

## Getting Started (local)
1) Python env
```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
