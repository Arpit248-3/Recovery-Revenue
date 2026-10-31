"""
Database Repositories for WAPSI Multi-Tenant Persistence Layer.
Project: ffgsrwjhguvubmhuefyj (Razorpay AI Buildathon 2026 - Track 3)

Implements clean data access patterns for:
  - Tenant Merchants & Configurations
  - Pseudonymized Customers
  - Integer-Paise Transactions
  - Causal Decisions Snapshot
  - Durable Multi-Provider Webhook Inbox Deduplication
  - API Idempotency Locks
  - Transactional Recovery Outbox
  - Tamper-Evident Audit Ledger Blocks
  - Contextual Bandit Weights
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import desc, select, text
from sqlalchemy.orm import Session

from wapsi.core.config import get_settings
from wapsi.db.models import (
    AuditLedgerBlockModel,
    BanditWeightModel,
    CausalDecisionModel,
    CustomerModel,
    IdempotencyKeyModel,
    MerchantConfigurationModel,
    MerchantMembershipModel,
    MerchantModel,
    PaymentOutcomeModel,
    RecoveryDispatchModel,
    RecoveryOutboxModel,
    TransactionModel,
    WebhookInboxModel,
)

logger = logging.getLogger("wapsi.repository")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


# ==============================================================================
# 1. MERCHANT REPOSITORY
# ==============================================================================
class MerchantRepository:

    @staticmethod
    def get_by_code(session: Session, merchant_code: str) -> Optional[MerchantModel]:
        stmt = select(MerchantModel).where(MerchantModel.merchant_code == merchant_code)
        return session.execute(stmt).scalar_one_or_none()

    @staticmethod
    def get_by_id(session: Session, merchant_id: uuid.UUID) -> Optional[MerchantModel]:
        stmt = select(MerchantModel).where(MerchantModel.id == merchant_id)
        return session.execute(stmt).scalar_one_or_none()

    @staticmethod
    def get_or_create_default(session: Session) -> MerchantModel:
        """Ensures the default development merchant exists."""
        default_code = "MRC_928374"
        merchant = MerchantRepository.get_by_code(session, default_code)
        if not merchant:
            merchant = MerchantModel(
                merchant_code=default_code,
                name="Acme Global Technologies",
                business_type="Enterprise SaaS & Subscriptions",
                industry="FinTech / Ecommerce",
                website="https://acmeglobal.io",
                registered_email="compliance@acmeglobal.io",
                country="India",
                currency="INR",
                timezone="Asia/Kolkata",
                status="ACTIVE",
            )
            session.add(merchant)
            session.flush()

            # Create default configuration
            cfg = MerchantConfigurationModel(
                merchant_id=merchant.id,
                recovery_enabled_percent=84,
                confidence_threshold_percent=80,
                min_uplift_threshold_percent=12,
                retry_attempt_limit=3,
                contact_budget_per_customer=2,
                min_ivr_amount_paise=150000,
                default_merchant_margin_basis_points=2000,
            )
            session.add(cfg)
            session.flush()

        return merchant

    @staticmethod
    def get_configuration(session: Session, merchant_id: uuid.UUID) -> Optional[MerchantConfigurationModel]:
        stmt = select(MerchantConfigurationModel).where(MerchantConfigurationModel.merchant_id == merchant_id)
        return session.execute(stmt).scalar_one_or_none()


# ==============================================================================
# 2. CUSTOMER REPOSITORY (Pseudonymized Identity)
# ==============================================================================
class CustomerRepository:

    @staticmethod
    def compute_pseudonym(merchant_id: uuid.UUID, customer_identifier: str) -> str:
        """Computes deterministic merchant-scoped customer pseudonym using HMAC-SHA256."""
        settings = get_settings()
        salt = settings.customer_hash_salt.get_secret_value().encode("utf-8")
        raw_msg = f"{merchant_id}:{customer_identifier}".encode("utf-8")
        return hmac.new(salt, raw_msg, hashlib.sha256).hexdigest()

    @staticmethod
    def get_or_create_customer(
        session: Session,
        merchant_id: uuid.UUID,
        merchant_customer_id: str,
        masked_identifier: Optional[str] = None,
        account_age_days: int = 0,
    ) -> CustomerModel:
        stmt = select(CustomerModel).where(
            CustomerModel.merchant_id == merchant_id,
            CustomerModel.merchant_customer_id == merchant_customer_id,
        )
        customer = session.execute(stmt).scalar_one_or_none()
        if not customer:
            pseudonym = CustomerRepository.compute_pseudonym(merchant_id, merchant_customer_id)
            masked = masked_identifier or f"Cust_{merchant_customer_id[:4]}****"
            customer = CustomerModel(
                merchant_id=merchant_id,
                merchant_customer_id=merchant_customer_id,
                customer_pseudonym=pseudonym,
                masked_identifier=masked,
                account_age_days=account_age_days,
            )
            session.add(customer)
            session.flush()
        return customer

    @staticmethod
    def update_opt_out(session: Session, merchant_id: uuid.UUID, customer_id: uuid.UUID, opted_out: bool) -> None:
        stmt = select(CustomerModel).where(
            CustomerModel.merchant_id == merchant_id,
            CustomerModel.id == customer_id,
        )
        cust = session.execute(stmt).scalar_one_or_none()
        if cust:
            cust.opted_out = opted_out
            cust.consent_status = "OPTED_OUT" if opted_out else "ACTIVE_CONSENT"
            cust.opted_out_at = _utc_now() if opted_out else None
            session.flush()


# ==============================================================================
# 3. TRANSACTION REPOSITORY (Monetary Integer Paise)
# ==============================================================================
class TransactionRepository:

    @staticmethod
    def create_transaction(
        session: Session,
        merchant_id: uuid.UUID,
        customer_id: uuid.UUID,
        payment_id: str,
        amount_paise: int,
        payment_method: str = "upi",
        error_code: str = "UPI_APP_TIMEOUT",
        error_category: str = "FRICTION_OTP_UX",
        error_description: Optional[str] = None,
        hour_of_day: int = 14,
        is_dnd_window: bool = False,
        status: str = "FAILED",
    ) -> TransactionModel:
        if amount_paise <= 0:
            raise ValueError(f"Transaction amount in paise must be strictly positive, got: {amount_paise}")

        tx = TransactionModel(
            merchant_id=merchant_id,
            customer_id=customer_id,
            payment_id=payment_id,
            amount_paise=amount_paise,
            payment_method=payment_method,
            error_code=error_code,
            error_category=error_category,
            error_description=error_description,
            hour_of_day=hour_of_day,
            is_dnd_window=is_dnd_window,
            status=status,
        )
        session.add(tx)
        session.flush()
        return tx

    @staticmethod
    def get_by_payment_id(session: Session, merchant_id: uuid.UUID, payment_id: str) -> Optional[TransactionModel]:
        stmt = select(TransactionModel).where(
            TransactionModel.merchant_id == merchant_id,
            TransactionModel.payment_id == payment_id,
        )
        return session.execute(stmt).scalar_one_or_none()


# ==============================================================================
# 4. CAUSAL DECISION REPOSITORY
# ==============================================================================
class CausalDecisionRepository:

    @staticmethod
    def create_decision(session: Session, decision_attrs: Dict[str, Any]) -> CausalDecisionModel:
        defaults = {
            "causal_uplift_tau_basis_points": 2800,
            "baseline_prob_basis_points": 1500,
            "expected_prob_basis_points": 4300,
            "conformal_interval": [0.20, 0.36],
            "confidence_tier": "HIGH",
            "conformal_calibration_status": "CALIBRATED_NOMINAL_90",
            "net_expected_utility_paise": 10000,
            "plain_english_rationale": "Recommended based on optimal causal uplift estimation.",
            "localized_customer_copy": {},
        }
        full_attrs = {**defaults, **decision_attrs}
        decision = CausalDecisionModel(**full_attrs)
        session.add(decision)
        session.flush()
        return decision

    @staticmethod
    def get_by_decision_id(session: Session, decision_id: str) -> Optional[CausalDecisionModel]:
        stmt = select(CausalDecisionModel).where(CausalDecisionModel.decision_id == decision_id)
        return session.execute(stmt).scalar_one_or_none()


# ==============================================================================
# 5. WEBHOOK INBOX REPOSITORY (Durable Event Deduplication)
# ==============================================================================
class WebhookInboxRepository:

    @staticmethod
    def record_and_deduplicate(
        session: Session,
        provider: str,
        environment: str,
        payment_id: str,
        event_type: str,
        nonce: str,
        signature: str,
        payload_sanitized: Dict[str, Any],
        merchant_id: Optional[uuid.UUID] = None,
        signature_verified: bool = True,
    ) -> Tuple[WebhookInboxModel, bool]:
        """
        Durable webhook deduplication:
        Returns:
            (record, is_new: bool)
            If is_new is False, event is an idempotent duplicate and must NOT trigger side-effects.
        """
        stmt = select(WebhookInboxModel).where(
            WebhookInboxModel.provider == provider,
            WebhookInboxModel.environment == environment,
            WebhookInboxModel.payment_id == payment_id,
            WebhookInboxModel.event_type == event_type,
            WebhookInboxModel.nonce == nonce,
        )
        existing = session.execute(stmt).scalar_one_or_none()
        if existing:
            return existing, False

        record = WebhookInboxModel(
            merchant_id=merchant_id,
            provider=provider,
            environment=environment,
            event_id=f"{provider}_{payment_id}_{nonce}",
            event_type=event_type,
            payment_id=payment_id,
            nonce=nonce,
            signature=signature,
            signature_verified=signature_verified,
            status="RECEIVED",
            payload_sanitized=payload_sanitized,
        )
        session.add(record)
        session.flush()
        return record, True

    @staticmethod
    def mark_processed(session: Session, inbox_id: uuid.UUID, status: str = "PROCESSED") -> None:
        stmt = select(WebhookInboxModel).where(WebhookInboxModel.id == inbox_id)
        record = session.execute(stmt).scalar_one_or_none()
        if record:
            record.status = status
            record.processed_at = _utc_now()
            session.flush()


# ==============================================================================
# 6. IDEMPOTENCY REPOSITORY
# ==============================================================================
class IdempotencyRepository:

    @staticmethod
    def check_or_create(
        session: Session,
        merchant_id: uuid.UUID,
        idempotency_key: str,
        request_path: str,
        request_payload: Any,
        ttl_seconds: int = 86400,
    ) -> Tuple[IdempotencyKeyModel, bool]:
        """
        Returns (record, is_new).
        If not new and status == 'COMPLETED', cached response is safe to return.
        """
        now = _utc_now()
        stmt = select(IdempotencyKeyModel).where(
            IdempotencyKeyModel.merchant_id == merchant_id,
            IdempotencyKeyModel.idempotency_key == idempotency_key,
        )
        existing = session.execute(stmt).scalar_one_or_none()

        if existing:
            # Check if expired (normalizing tz for SQLite and Postgres compatibility)
            exp = existing.expires_at
            if exp and exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if exp and exp < now:
                # Expired idempotency key: reset and reuse
                existing.status = "PROCESSING"
                existing.created_at = now
                existing.expires_at = now + timedelta(seconds=ttl_seconds)
                existing.response_status_code = None
                existing.response_body = None
                session.flush()
                return existing, True
            return existing, False

        # Compute SHA-256 hash of payload
        payload_bytes = json.dumps(request_payload, sort_keys=True).encode("utf-8") if request_payload else b""
        req_hash = hashlib.sha256(payload_bytes).hexdigest()

        new_entry = IdempotencyKeyModel(
            merchant_id=merchant_id,
            idempotency_key=idempotency_key,
            request_path=request_path,
            request_hash=req_hash,
            status="PROCESSING",
            expires_at=now + timedelta(seconds=ttl_seconds),
        )
        session.add(new_entry)
        session.flush()
        return new_entry, True

    @staticmethod
    def complete(
        session: Session,
        idempotency_id: uuid.UUID,
        status_code: int,
        response_body: Dict[str, Any],
    ) -> None:
        stmt = select(IdempotencyKeyModel).where(IdempotencyKeyModel.id == idempotency_id)
        record = session.execute(stmt).scalar_one_or_none()
        if record:
            record.status = "COMPLETED"
            record.response_status_code = status_code
            record.response_body = response_body
            session.flush()


# ==============================================================================
# 7. RECOVERY OUTBOX REPOSITORY (Transactional Outbox Pattern)
# ==============================================================================
class RecoveryOutboxRepository:

    @staticmethod
    def enqueue(
        session: Session,
        merchant_id: uuid.UUID,
        decision_id: uuid.UUID,
        idempotency_key: str,
        action: str,
        channel: str,
        recipient_masked: str,
        message_payload: Dict[str, Any],
    ) -> RecoveryOutboxModel:
        outbox = RecoveryOutboxModel(
            merchant_id=merchant_id,
            decision_id=decision_id,
            idempotency_key=idempotency_key,
            action=action,
            channel=channel,
            recipient_masked=recipient_masked,
            message_payload=message_payload,
            status="QUEUED",
        )
        session.add(outbox)
        session.flush()
        return outbox

    @staticmethod
    def fetch_queued(session: Session, limit: int = 50) -> List[RecoveryOutboxModel]:
        now = _utc_now()
        stmt = (
            select(RecoveryOutboxModel)
            .where(
                RecoveryOutboxModel.status.in_(["QUEUED", "RETRY"]),
                RecoveryOutboxModel.next_attempt_at <= now,
            )
            .order_by(RecoveryOutboxModel.next_attempt_at.asc())
            .limit(limit)
        )
        return list(session.execute(stmt).scalars().all())

    @staticmethod
    def transition_status(
        session: Session,
        outbox_id: uuid.UUID,
        new_status: str,
        last_error: Optional[str] = None,
        retry_delay_seconds: int = 60,
    ) -> None:
        stmt = select(RecoveryOutboxModel).where(RecoveryOutboxModel.id == outbox_id)
        item = session.execute(stmt).scalar_one_or_none()
        if not item:
            return

        item.status = new_status
        if last_error:
            item.last_error = last_error

        if new_status == "RETRY":
            item.retry_count += 1
            if item.retry_count >= item.max_retries:
                item.status = "DEAD_LETTER"
            else:
                # Exponential backoff
                backoff = retry_delay_seconds * (2 ** (item.retry_count - 1))
                item.next_attempt_at = _utc_now() + timedelta(seconds=backoff)
        elif new_status == "SENT":
            item.last_error = None

        session.flush()


# ==============================================================================
# 8. AUDIT LEDGER REPOSITORY (Append-Only Cryptographic Chain)
# ==============================================================================
class AuditLedgerRepository:

    @staticmethod
    def append_block(
        session: Session,
        event_type: str,
        data_payload: Dict[str, Any],
        merchant_id: Optional[uuid.UUID] = None,
    ) -> AuditLedgerBlockModel:
        """Appends a new cryptographically chained block to the audit ledger."""
        # Under PostgreSQL, acquire transaction-scoped advisory lock to prevent concurrent index collision
        try:
            bind = session.get_bind()
            if bind and "postgresql" in str(bind.url):
                lock_id = (hash(f"audit_ledger_{merchant_id}") & 0x7FFFFFFF)
                session.execute(text("SELECT pg_advisory_xact_lock(:lock_id)"), {"lock_id": lock_id})
        except Exception:
            pass  # Fallback gracefully if dialect doesn't support advisory locks

        # Find latest block index and hash
        stmt = (
            select(AuditLedgerBlockModel)
            .where(AuditLedgerBlockModel.merchant_id == merchant_id)
            .order_by(desc(AuditLedgerBlockModel.block_index))
            .limit(1)
        )
        last_block = session.execute(stmt).scalar_one_or_none()

        if last_block:
            next_index = last_block.block_index + 1
            prev_hash = last_block.block_hash
        else:
            next_index = 0
            prev_hash = "0" * 64

        now = _utc_now()
        timestamp_str = now.isoformat()

        # Compute SHA-256 block hash
        canonical_data = json.dumps(data_payload, sort_keys=True)
        raw_to_hash = f"{next_index}:{prev_hash}:{timestamp_str}:{event_type}:{canonical_data}"
        block_hash = hashlib.sha256(raw_to_hash.encode("utf-8")).hexdigest()

        block = AuditLedgerBlockModel(
            merchant_id=merchant_id,
            block_index=next_index,
            previous_hash=prev_hash,
            block_hash=block_hash,
            event_type=event_type,
            data_payload=data_payload,
            timestamp=now,
        )
        session.add(block)
        session.flush()
        return block

    @staticmethod
    def verify_integrity(session: Session, merchant_id: Optional[uuid.UUID] = None) -> Dict[str, Any]:
        """Validates the continuous SHA-256 hash chaining of all blocks in database."""
        stmt = (
            select(AuditLedgerBlockModel)
            .where(AuditLedgerBlockModel.merchant_id == merchant_id)
            .order_by(AuditLedgerBlockModel.block_index.asc())
        )
        blocks = list(session.execute(stmt).scalars().all())

        if not blocks:
            return {"is_valid": True, "blocks_count": 0, "message": "No blocks in ledger."}

        prev_hash = "0" * 64
        for idx, block in enumerate(blocks):
            if block.block_index != idx:
                return {
                    "is_valid": False,
                    "error": f"Sequence break at block index {block.block_index}, expected {idx}",
                    "corrupt_index": block.block_index,
                }
            if block.previous_hash != prev_hash:
                return {
                    "is_valid": False,
                    "error": f"Hash chain broken at index {idx}! Expected previous {prev_hash}, got {block.previous_hash}",
                    "corrupt_index": idx,
                }
            prev_hash = block.block_hash

        return {"is_valid": True, "blocks_count": len(blocks), "latest_hash": prev_hash}

    @staticmethod
    def get_recent_blocks(session: Session, merchant_id: Optional[uuid.UUID] = None, limit: int = 50) -> List[AuditLedgerBlockModel]:
        stmt = (
            select(AuditLedgerBlockModel)
            .where(AuditLedgerBlockModel.merchant_id == merchant_id)
            .order_by(desc(AuditLedgerBlockModel.block_index))
            .limit(limit)
        )
        return list(session.execute(stmt).scalars().all())


# ==============================================================================
# 9. BANDIT WEIGHTS REPOSITORY (Online Learning State Persistence)
# ==============================================================================
class BanditRepository:

    @staticmethod
    def save_action_weights(
        session: Session,
        merchant_id: uuid.UUID,
        model_version: str,
        action: str,
        matrix_a: List[List[float]],
        vector_b: List[float],
        alpha: float = 0.8,
        updates_count: int = 1,
    ) -> BanditWeightModel:
        stmt = select(BanditWeightModel).where(
            BanditWeightModel.merchant_id == merchant_id,
            BanditWeightModel.model_version == model_version,
            BanditWeightModel.action == action,
        )
        record = session.execute(stmt).scalar_one_or_none()
        if record:
            record.matrix_a = matrix_a
            record.vector_b = vector_b
            record.alpha = alpha
            record.total_updates += updates_count
            record.last_updated_at = _utc_now()
        else:
            record = BanditWeightModel(
                merchant_id=merchant_id,
                model_version=model_version,
                action=action,
                matrix_a=matrix_a,
                vector_b=vector_b,
                alpha=alpha,
                total_updates=updates_count,
            )
            session.add(record)
        session.flush()
        return record

    @staticmethod
    def load_action_weights(
        session: Session,
        merchant_id: uuid.UUID,
        model_version: str,
        action: str,
    ) -> Optional[BanditWeightModel]:
        stmt = select(BanditWeightModel).where(
            BanditWeightModel.merchant_id == merchant_id,
            BanditWeightModel.model_version == model_version,
            BanditWeightModel.action == action,
        )
        return session.execute(stmt).scalar_one_or_none()

    @staticmethod
    def load_all_weights(
        session: Session,
        merchant_id: uuid.UUID,
        model_version: str = "v1.0.0",
    ) -> Dict[str, Dict[str, Any]]:
        stmt = select(BanditWeightModel).where(
            BanditWeightModel.merchant_id == merchant_id,
            BanditWeightModel.model_version == model_version,
        )
        records = session.execute(stmt).scalars().all()
        return {
            r.action: {
                "matrix_a": r.matrix_a,
                "vector_b": r.vector_b,
                "alpha": float(r.alpha),
                "total_updates": r.total_updates,
            }
            for r in records
        }

