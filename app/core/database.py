from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from dotenv import load_dotenv
import os

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")

# SQLite requires check_same_thread=False for multi-threaded use (asyncio + sync SQLAlchemy).
# PostgreSQL / other drivers use connection pooling — pool_size/max_overflow are meaningful there.
_is_sqlite = DATABASE_URL and DATABASE_URL.startswith("sqlite")

_engine_kwargs: dict = {"pool_pre_ping": True}

if _is_sqlite:
    # SQLite: disable NullPool / threading restriction; use StaticPool for testing if needed
    _engine_kwargs["connect_args"] = {"check_same_thread": False}
else:
    # PostgreSQL / MySQL etc.: full connection pool
    _engine_kwargs["pool_size"] = 10
    _engine_kwargs["max_overflow"] = 20

engine = create_engine(DATABASE_URL, **_engine_kwargs)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)

Base = declarative_base()


def get_db():
    """
    FastAPI dependency that yields a SQLAlchemy session and always closes it.
    Use with: db: Session = Depends(get_db)
    """
    db: Session = SessionLocal()
    try:
        yield db
    finally:
        db.close()


