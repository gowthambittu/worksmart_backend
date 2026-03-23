import subprocess
import sys
from pathlib import Path

from sqlalchemy import inspect
from sqlalchemy import text

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from flaskr import app, db


def run_cmd(cmd):
    completed = subprocess.run(cmd, check=False)
    if completed.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(cmd)}")


def main():
    with app.app_context():
        inspector = inspect(db.engine)
        tables = set(inspector.get_table_names())
        alembic_rows = []
        if "alembic_version" in tables:
            alembic_rows = db.session.execute(
                text("SELECT version_num FROM alembic_version")
            ).fetchall()

    has_alembic_version = "alembic_version" in tables
    has_existing_schema = len(tables) > 0
    has_alembic_row = len(alembic_rows) > 0

    # Existing DB without alembic metadata: align migration state first.
    if has_existing_schema and (not has_alembic_version or not has_alembic_row):
        print("Detected existing schema without valid alembic state. Stamping head.")
        run_cmd(["flask", "--app", "flaskr", "db", "stamp", "head"])

    print("Running database migrations.")
    run_cmd(["flask", "--app", "flaskr", "db", "upgrade"])
    print("Migration step completed.")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Migration failed: {exc}", file=sys.stderr)
        sys.exit(1)
