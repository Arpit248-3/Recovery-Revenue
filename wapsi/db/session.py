"""
Database Session & Connection Lifecycle Management for WAPSI.
Project: ffgsrwjhguvubmhuefyj (Razorpay AI Buildathon 2026 - Track 3)

Provides thread-safe connection pooling, transaction boundaries,
fail-safe in-memory SQLite fallbacks for offline testing, and health telemetry.
"""

from __future__ import annotations

import logging
import time
from contextlib import contextmanager
from typing import Any, Dict, Generator, Optional

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from wapsi.core.config import get_settings
from wapsi.db.models import Base

logger = logging.getLogger("wapsi.db")


class DatabaseManager:
    """
    Manages SQLAlchemy engine lifecycle, session factories, and database connectivity.
    """

    def __init__(self, database_url: Optional[str] = None):
        settings = get_settings()
        url = database_url or settings.database_url

        self.is_fallback_mode = False
        if not url:
            # Fallback to local in-memory SQLite for isolated local testing / development
            url = "sqlite:///:memory:"
            self.is_fallback_mode = True
            logger.info("DATABASE_URL not configured. Initialized safe local SQLite fallback engine.")
        elif url.startswith("postgres://"):
            # SQLAlchemy 2.0 requires postgresql+psycopg2:// instead of postgres://
            url = url.replace("postgres://", "postgresql+psycopg2://", 1)
        elif url.startswith("postgresql://") and not url.startswith("postgresql+"):
            url = url.replace("postgresql://", "postgresql+psycopg2://", 1)

        self.database_url = url
        
        # Engine configuration
        connect_args = {}
        if "sqlite" in url:
            connect_args = {"check_same_thread": False}
        elif "postgresql" in url:
            # Check driver availability
            try:
                import psycopg2  # noqa: F401
            except ImportError:
                logger.warning(
                    "DATABASE_URL is configured for PostgreSQL, but 'psycopg2' driver is not installed in the environment. "
                    "Install with: pip install psycopg2-binary>=2.9.9"
                )

        self.engine: Engine = create_engine(
            self.database_url,
            connect_args=connect_args,
            pool_pre_ping=True,
            echo=False,
        )

        self.session_factory = sessionmaker(
            bind=self.engine,
            autocommit=False,
            autoflush=False,
            expire_on_commit=False,
        )

        # Initialize schema tables if running in SQLite fallback mode
        if self.is_fallback_mode or ":memory:" in self.database_url:
            self.init_schema()

    def init_schema(self) -> None:
        """Creates tables locally when running in local development / test mode."""
        Base.metadata.create_all(self.engine)
        logger.info("Local database schema tables initialized successfully.")

    def create_all_tables(self) -> None:
        """Alias for init_schema."""
        self.init_schema()

    def drop_all_tables(self) -> None:
        """Drops tables locally (used in tests)."""
        Base.metadata.drop_all(self.engine)

    @contextmanager
    def session_scope(self) -> Generator[Session, None, None]:
        """
        Context manager for transactional database operations.
        Automatically commits on successful block exit; rolls back on exception.
        """
        session = self.session_factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def get_session(self) -> Session:
        """Returns a new session instance. Caller must close the session."""
        return self.session_factory()

    def ping(self) -> Dict[str, Any]:
        """
        Verifies database health and measures round-trip query latency.
        """
        start_time = time.time()
        try:
            with self.session_scope() as session:
                session.execute(text("SELECT 1"))
            duration_ms = round((time.time() - start_time) * 1000, 2)
            return {
                "status": "healthy",
                "connected": True,
                "dialect": self.engine.dialect.name,
                "latency_ms": duration_ms,
                "is_fallback": self.is_fallback_mode,
            }
        except Exception as e:
            logger.error(f"Database health ping failed: {e}")
            return {
                "status": "unhealthy",
                "connected": False,
                "dialect": self.engine.dialect.name,
                "error": str(e),
                "is_fallback": self.is_fallback_mode,
            }


# Module singleton manager
_db_manager: Optional[DatabaseManager] = None


def get_db_manager() -> DatabaseManager:
    global _db_manager
    if _db_manager is None:
        _db_manager = DatabaseManager()
    return _db_manager


def get_db() -> Generator[Session, None, None]:
    """FastAPI route dependency yielding a scoped database session."""
    manager = get_db_manager()
    with manager.session_scope() as session:
        yield session

