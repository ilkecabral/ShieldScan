"""
database.py — SQLAlchemy engine + session setup
Switch from SQLite to PostgreSQL by changing DATABASE_URL in .env
"""

import os
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv

load_dotenv()

# Default: SQLite in the backend folder (no setup needed)
# For PostgreSQL: DATABASE_URL=postgresql://user:pass@localhost/shieldscan
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./shieldscan.db")

# SQLite needs check_same_thread=False; other DBs don't need this kwarg
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, connect_args=connect_args)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


# FastAPI dependency — use with Depends(get_db)
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
