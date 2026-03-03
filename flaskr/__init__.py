import os
import json
import time
import uuid
from collections import defaultdict
from dotenv import load_dotenv
from urllib.parse import quote
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask import Flask, g, jsonify, request
import logging
from flask_migrate import Migrate
from sqlalchemy import text



load_dotenv() 

# def create_app(test_config=None):
#     # create and configure the app
app = Flask(__name__)


class JsonFormatter(logging.Formatter):
    def format(self, record):
        payload = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        request_id = getattr(record, "request_id", None)
        if request_id:
            payload["request_id"] = request_id
        for key in ("method", "path", "status_code", "duration_ms", "remote_addr"):
            value = getattr(record, key, None)
            if value is not None:
                payload[key] = value
        return json.dumps(payload)

# Allow local dev and production UI origins. Override with CORS_ORIGINS env:
# CORS_ORIGINS="http://localhost:3000,https://smartworkmanagement.com"
allowed_origins = [
    origin.strip()
    for origin in os.getenv(
        "CORS_ORIGINS",
        "http://localhost:3000,http://127.0.0.1:3000,https://smartworkmanagement.com",
    ).split(",")
    if origin.strip()
]

CORS(
    app,
    resources={
        r"/auth/*": {"origins": allowed_origins},
        r"/api/*": {"origins": allowed_origins},
        r"/hello": {"origins": allowed_origins},
        r"/healthz": {"origins": allowed_origins},
        r"/readyz": {"origins": allowed_origins},
        r"/metrics": {"origins": allowed_origins},
    },
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)
db_password = quote(os.getenv('MYSQL_PASSWORD'))
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI').format(db_password)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.getenv('IMG_FOLDER')
app.config['OUTBOUND_FOLDER'] = os.getenv('OUTBOUND_FOLDER')
db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)

# In-process metrics for operational visibility.
METRICS = {
    "requests_total": defaultdict(int),
    "request_errors_total": defaultdict(int),
    "request_latency_ms_sum": defaultdict(float),
    "request_latency_ms_count": defaultdict(int),
}

# Configure application logger once.
log_level = os.getenv("LOG_LEVEL", "INFO").upper()
app.logger.handlers = []
app.logger.setLevel(getattr(logging, log_level, logging.INFO))
handler = logging.StreamHandler()
handler.setFormatter(JsonFormatter())
app.logger.addHandler(handler)
app.logger.propagate = False


@app.before_request
def track_request_start():
    g.request_start_time = time.time()
    g.request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())


@app.after_request
def emit_access_log(response):
    start = getattr(g, "request_start_time", None)
    duration_ms = round((time.time() - start) * 1000, 2) if start else 0.0
    path = request.path
    method = request.method
    status_code = response.status_code

    METRICS["requests_total"][(method, path, status_code)] += 1
    METRICS["request_latency_ms_sum"][(method, path)] += duration_ms
    METRICS["request_latency_ms_count"][(method, path)] += 1
    if status_code >= 500:
        METRICS["request_errors_total"][(method, path, status_code)] += 1

    app.logger.info(
        "request_completed",
        extra={
            "request_id": getattr(g, "request_id", None),
            "method": method,
            "path": path,
            "status_code": status_code,
            "duration_ms": duration_ms,
            "remote_addr": request.remote_addr,
        },
    )
    response.headers["X-Request-ID"] = getattr(g, "request_id", "")
    return response

@app.route('/hello')
def hello():
    return ("Hello World")


@app.route('/healthz')
def healthz():
    return jsonify({"status": "ok"}), 200


@app.route('/readyz')
def readyz():
    try:
        db.session.execute(text("SELECT 1"))
        return jsonify({"status": "ready"}), 200
    except Exception as e:
        app.logger.error(
            "readiness_check_failed",
            extra={"request_id": getattr(g, "request_id", None)},
        )
        return jsonify({"status": "not_ready", "error": str(e)}), 503


@app.route('/metrics')
def metrics():
    lines = []
    lines.append("# HELP app_requests_total Total HTTP requests by method, path, and status.")
    lines.append("# TYPE app_requests_total counter")
    for (method, path, status), value in METRICS["requests_total"].items():
        lines.append(
            f'app_requests_total{{method="{method}",path="{path}",status="{status}"}} {value}'
        )

    lines.append("# HELP app_request_errors_total Total 5xx HTTP responses.")
    lines.append("# TYPE app_request_errors_total counter")
    for (method, path, status), value in METRICS["request_errors_total"].items():
        lines.append(
            f'app_request_errors_total{{method="{method}",path="{path}",status="{status}"}} {value}'
        )

    lines.append("# HELP app_request_latency_ms_sum Total request latency in milliseconds.")
    lines.append("# TYPE app_request_latency_ms_sum counter")
    for (method, path), value in METRICS["request_latency_ms_sum"].items():
        lines.append(
            f'app_request_latency_ms_sum{{method="{method}",path="{path}"}} {value}'
        )

    lines.append("# HELP app_request_latency_ms_count Request latency observation count.")
    lines.append("# TYPE app_request_latency_ms_count counter")
    for (method, path), value in METRICS["request_latency_ms_count"].items():
        lines.append(
            f'app_request_latency_ms_count{{method="{method}",path="{path}"}} {value}'
        )

    return ("\n".join(lines) + "\n", 200, {"Content-Type": "text/plain; version=0.0.4"})

# Import and register blueprints, configure other app settings, etc.
from . import views, views_outbound,views_workRecord,views_properties
app.register_blueprint(views.auth_blueprint)
app.register_blueprint(views_properties.property_blueprint)
app.register_blueprint(views_workRecord.work_record_blueprint)
app.register_blueprint(views_outbound.outbound_record_blueprint)
