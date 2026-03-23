# Worksmart Backend

## Runtime
- Preferred Python: `3.12`
- Create venv:
  - `python3.12 -m venv .venv312`
  - `source .venv312/bin/activate`
- Install dependencies:
  - `pip install -r requirements.txt`

## Environment
Environment loading order:
- If `ENV_FILE` is set, backend loads that file.
- Else if `APP_ENV=production`, backend loads `.env.production`.
- Else backend loads `.env.local` (and then `.env` as fallback).

Recommended setup:
- Copy `.env.local.example` to `.env.local` for local development.
- Copy `.env.production.example` to `.env.production` for production values.

Required keys:
- `MYSQL_PASSWORD`
- `SQLALCHEMY_DATABASE_URI`
- `SECRET_KEY`
- `BCRYPT_LOG_ROUNDS`
- `IMG_FOLDER`
- `OUTBOUND_FOLDER`
- `CLOUDINARY_CLOUD_NAME`
- `CLOUDINARY_API_KEY`
- `CLOUDINARY_API_SECRET`
- `CORS_ORIGINS`
- `LOG_LEVEL`

## Run
- Dev server:
  - `flask --app flaskr run --debug --port 8080`

## Render Deployment (Free Tier)
- This repo includes `render.yaml` for a Python web service.
- Build command: `pip install -r requirements.txt`
- Start command: `gunicorn -w ${WEB_CONCURRENCY:-2} -b 0.0.0.0:${PORT:-10000} flaskr:app`
- Health check: `/healthz`

Set these environment variables in Render:
- `SQLALCHEMY_DATABASE_URI` (Clever example):
  - `mysql+mysqlconnector://<user>:<password>@<host>:3306/<db>`
- `MYSQL_PASSWORD` (only needed if your URI uses `${MYSQL_PASSWORD}` placeholder)
- `SECRET_KEY`
- `BCRYPT_LOG_ROUNDS` (e.g. `12`)
- `CORS_ORIGINS` (comma-separated, include your Render frontend URL)
- `CLOUDINARY_CLOUD_NAME`
- `CLOUDINARY_API_KEY`
- `CLOUDINARY_API_SECRET`
- `LOG_LEVEL` (e.g. `INFO`)

## Observability

### Request IDs
- Incoming `X-Request-ID` is accepted if present.
- If absent, server generates one.
- Response always includes `X-Request-ID`.

### Health Endpoints
- Liveness: `GET /healthz`
- Readiness: `GET /readyz` (checks DB connectivity)

### Metrics
- Prometheus-style endpoint: `GET /metrics`
- Includes:
  - `app_requests_total`
  - `app_request_errors_total`
  - `app_request_latency_ms_sum`
  - `app_request_latency_ms_count`

### Logging
- Structured JSON logs.
- Access logs include:
  - method, path, status, duration, remote address, request_id
- Exception logs include:
  - event name + request_id
