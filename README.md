# Worksmart Backend

## Runtime
- Preferred Python: `3.12`
- Create venv:
  - `python3.12 -m venv .venv312`
  - `source .venv312/bin/activate`
- Install dependencies:
  - `pip install -r requirements.txt`

## Environment
Copy `.env.example` to `.env` and fill values.

Required keys:
- `MYSQL_PASSWORD`
- `SQLALCHEMY_DATABASE_URI`
- `SECRET_KEY`
- `BCRYPT_LOG_ROUNDS`
- `IMG_FOLDER`
- `OUTBOUND_FOLDER`
- `CORS_ORIGINS`
- `LOG_LEVEL`

## Run
- Dev server:
  - `flask --app flaskr run --debug --port 8080`

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
