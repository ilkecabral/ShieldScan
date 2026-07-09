"""
database.py — SQLAlchemy engine + session setup

Switch from SQLite (dev) to PostgreSQL (prod) by setting DATABASE_URL in .env:
  dev:  sqlite:///./shieldscan.db
  prod: postgresql://shieldscan:PASS@rds-endpoint:5432/shieldscan

Migrations are now handled by Alembic (alembic/), not by this file.
Run: alembic upgrade head
"""

import os
import logging
from sqlalchemy import create_engine, text, inspect
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./shieldscan.db")

# ── Connection args ────────────────────────────────────────
# SQLite needs check_same_thread=False for FastAPI's thread model.
# PostgreSQL uses a real connection pool — tune pool_size for your load.
if DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}
    engine = create_engine(
        DATABASE_URL,
        connect_args=connect_args,
    )
    logger.warning(
        "Using SQLite — suitable for local dev only. "
        "Set DATABASE_URL to a PostgreSQL connection string for staging/production."
    )
else:
    engine = create_engine(
        DATABASE_URL,
        pool_size=10,           # connections kept open
        max_overflow=20,        # extra connections allowed under load
        pool_pre_ping=True,     # verify connection is alive before use (handles DB restarts)
        pool_recycle=1800,      # recycle connections every 30 min (avoid "server closed connection")
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def run_migrations():
    """
    Backward-compatibility shim: apply any SQLite column migrations that existed
    before Alembic was introduced.

    When DATABASE_URL is PostgreSQL, this is a no-op — Alembic handles all
    schema changes via: alembic upgrade head

    Safe to call on every startup.
    """
    if not DATABASE_URL.startswith("sqlite"):
        # PostgreSQL: schema is managed by Alembic — don't touch it here
        return

    insp = inspect(engine)
    if "users" not in insp.get_table_names():
        return  # Table doesn't exist yet — create_all will handle it

    existing_cols = {col["name"] for col in insp.get_columns("users")}

    legacy_migrations = [
        ("email_verified",         "BOOLEAN DEFAULT 1"),
        ("email_verify_code",      "VARCHAR(8)"),
        ("email_verify_expires",   "DATETIME"),
        ("deleted_at",             "DATETIME"),
        ("recovery_token_hash",    "VARCHAR(64)"),
        ("recovery_token_expires", "DATETIME"),
        ("is_admin",               "BOOLEAN DEFAULT 0"),
        ("reset_token_hash",       "VARCHAR(64)"),
        ("reset_token_expires",    "DATETIME"),
    ]

    with engine.begin() as conn:
        for col_name, col_type in legacy_migrations:
            if col_name not in existing_cols:
                conn.execute(text(f"ALTER TABLE users ADD COLUMN {col_name} {col_type}"))
                logger.info("SQLite migration: added column users.%s", col_name)


# FastAPI dependency — use with Depends(get_db)
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
