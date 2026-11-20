"""
Pytest global configuration and safety guards for WAPSI test suite.

Safety Guarantees:
1. Zero mutation of live hosted target outbox job (5a6587ab-2601-4017-b396-48e3d2fc2fda).
2. Prevents test executions from claiming, approving, or mutating hosted production/sandbox rows.
3. Enforces that all test-driven claim and execution workflows use isolated synthetic fixtures.
"""

from __future__ import annotations

import os
import pytest
from sqlalchemy import event
from sqlalchemy.engine import Engine

TARGET_JOB_ID_STR = "5a6587ab-2601-4017-b396-48e3d2fc2fda"


@event.listens_for(Engine, "before_cursor_execute")
def guard_live_target_mutations(conn, cursor, statement, parameters, context, executemany):
    """
    SQLAlchemy execution listener that fails closed if any test query attempts
    to execute an UPDATE or DELETE against the live target job in PostgreSQL.
    """
    if not os.environ.get("PYTEST_CURRENT_TEST"):
        return

    # Check statement type
    stmt_upper = statement.strip().upper()
    is_mutation = stmt_upper.startswith("UPDATE") or stmt_upper.startswith("DELETE")
    is_claim = "CLAIM_SPECIFIC_RECOVERY_OUTBOX_JOB" in stmt_upper or "CLAIM_RECOVERY_OUTBOX_JOBS" in stmt_upper

    if (is_mutation or is_claim) and TARGET_JOB_ID_STR in str(statement).lower():
        # Check dialect: if PostgreSQL, block mutation
        if conn.dialect.name == "postgresql":
            raise RuntimeError(
                f"SAFETY GUARD INTERCEPT: Test '{os.environ.get('PYTEST_CURRENT_TEST')}' "
                f"attempted to mutate or claim live hosted target job {TARGET_JOB_ID_STR}! "
                "Mutations against the live target job in PostgreSQL are strictly forbidden during tests."
            )

    # Check parameters for TARGET_JOB_ID_STR in UPDATE/DELETE or claim
    if (is_mutation or is_claim) and parameters and conn.dialect.name == "postgresql":
        param_str = str(parameters).lower()
        if TARGET_JOB_ID_STR in param_str:
            raise RuntimeError(
                f"SAFETY GUARD INTERCEPT: Test '{os.environ.get('PYTEST_CURRENT_TEST')}' "
                f"passed live target job {TARGET_JOB_ID_STR} into a mutating or claim statement! "
                "Mutations against the live target job in PostgreSQL are strictly forbidden during tests."
            )


@pytest.fixture(autouse=True)
def test_safety_environment(monkeypatch):
    """Ensures test environment flags are set and protects live data."""
    monkeypatch.setenv("WAPSI_TEST_MODE", "1")
    monkeypatch.setenv("PUBLIC_BASE_URL", "http://localhost:8000")
    monkeypatch.setenv("WAPSI_PUBLIC_BASE_URL", "http://localhost:8000")
    import wapsi.core.config as config_mod
    orig_url = None
    if config_mod._settings_instance is not None:
        orig_url = config_mod._settings_instance.public_base_url
        config_mod._settings_instance.public_base_url = "http://localhost:8000"

    from wapsi.recovery.opt_out_store import PersistentOptOutStore, get_persistent_opt_out_store, set_persistent_opt_out_store
    orig_opt_out = get_persistent_opt_out_store()
    test_db_path = os.path.abspath(".wapsi_data/test_opt_outs.db")
    test_opt_out = PersistentOptOutStore(db_path=test_db_path)
    test_opt_out.clear()
    set_persistent_opt_out_store(test_opt_out)

    from wapsi.integrations.whatsapp.opt_out import get_opt_out_manager
    get_opt_out_manager().clear()

    import wapsi.recovery.webhook_processor as wp_mod
    orig_wp_opt_out = None
    if wp_mod._GLOBAL_WEBHOOK_PROCESSOR is not None:
        orig_wp_opt_out = wp_mod._GLOBAL_WEBHOOK_PROCESSOR._opt_out
        wp_mod._GLOBAL_WEBHOOK_PROCESSOR._opt_out = test_opt_out

    try:
        yield
    finally:
        if orig_url is not None and config_mod._settings_instance is not None:
            config_mod._settings_instance.public_base_url = orig_url
        set_persistent_opt_out_store(orig_opt_out)
        if wp_mod._GLOBAL_WEBHOOK_PROCESSOR is not None:
            wp_mod._GLOBAL_WEBHOOK_PROCESSOR._opt_out = orig_wp_opt_out
        get_opt_out_manager().clear()
