-- WAPSI Migration 3: Multi-Tenant Row-Level Security (RLS) & Cryptographic Immutability
-- Project: ffgsrwjhguvubmhuefyj (Razorpay AI Buildathon 2026 - Track 3)
-- Security: Explicit Tenant Authorization, Pinned search_path, Append-Only Tamper-Proof Audit

-- ==============================================================================
-- 1. SECURITY HELPER FUNCTIONS (search_path Pinned)
-- ==============================================================================

-- Resolves the active merchant context from session setting 'app.current_merchant_id'
CREATE OR REPLACE FUNCTION public.current_active_merchant_id()
RETURNS uuid
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_raw text;
BEGIN
    v_raw := current_setting('app.current_merchant_id', true);
    IF v_raw IS NULL OR v_raw = '' THEN
        RETURN NULL;
    END IF;
    RETURN v_raw::uuid;
EXCEPTION WHEN OTHERS THEN
    RETURN NULL;
END;
$$;

-- Validates whether auth.uid() has an active membership for target merchant with allowed roles
CREATE OR REPLACE FUNCTION public.has_merchant_role(target_merchant_id uuid, required_roles text[])
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    IF auth.uid() IS NULL OR target_merchant_id IS NULL THEN
        RETURN false;
    END IF;

    RETURN EXISTS (
        SELECT 1
        FROM public.merchant_memberships mm
        WHERE mm.merchant_id = target_merchant_id
          AND mm.user_id = auth.uid()
          AND mm.is_active = true
          AND mm.role = ANY(required_roles)
    );
END;
$$;


-- ==============================================================================
-- 2. ENABLE ROW-LEVEL SECURITY (All 15 Entities Enforced)
-- ==============================================================================
ALTER TABLE public.merchants ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.merchant_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.merchant_configurations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.merchant_api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.customers ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.transactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.model_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.causal_decisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.webhook_inbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.idempotency_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.recovery_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.recovery_dispatches ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.payment_outcomes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_ledger_blocks ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.bandit_weights ENABLE ROW LEVEL SECURITY;


-- ==============================================================================
-- 3. RLS POLICIES: MERCHANTS & MEMBERSHIPS
-- ==============================================================================

-- Merchants: Visible to active members
CREATE POLICY p_merchants_select ON public.merchants
    FOR SELECT
    TO authenticated
    USING (
        id = public.current_active_merchant_id()
        AND public.has_merchant_role(id, ARRAY['merchant_admin', 'recovery_operator', 'risk_officer', 'auditor', 'system_service'])
    );

CREATE POLICY p_merchants_update ON public.merchants
    FOR UPDATE
    TO authenticated
    USING (
        id = public.current_active_merchant_id()
        AND public.has_merchant_role(id, ARRAY['merchant_admin'])
    )
    WITH CHECK (
        id = public.current_active_merchant_id()
        AND public.has_merchant_role(id, ARRAY['merchant_admin'])
    );

-- Merchant Memberships: User can view their own memberships; Admin can view all for active merchant
CREATE POLICY p_memberships_select ON public.merchant_memberships
    FOR SELECT
    TO authenticated
    USING (
        user_id = auth.uid()
        OR (
            merchant_id = public.current_active_merchant_id()
            AND public.has_merchant_role(merchant_id, ARRAY['merchant_admin'])
        )
    );

CREATE POLICY p_memberships_admin_manage ON public.merchant_memberships
    FOR ALL
    TO authenticated
    USING (
        merchant_id = public.current_active_merchant_id()
        AND public.has_merchant_role(merchant_id, ARRAY['merchant_admin'])
    )
    WITH CHECK (
        merchant_id = public.current_active_merchant_id()
        AND public.has_merchant_role(merchant_id, ARRAY['merchant_admin'])
    );


-- ==============================================================================
-- 4. RLS POLICIES: CONFIGURATIONS & API KEYS
-- ==============================================================================

CREATE POLICY p_configurations_select ON public.merchant_configurations
    FOR SELECT
    TO authenticated
    USING (
        merchant_id = public.current_active_merchant_id()
        AND public.has_merchant_role(merchant_id, ARRAY['merchant_admin', 'recovery_operator', 'risk_officer', 'auditor'])
    );

CREATE POLICY p_configurations_update ON public.merchant_configurations
    FOR UPDATE
    TO authenticated
    USING (
        merchant_id = public.current_active_merchant_id()
        AND public.has_merchant_role(merchant_id, ARRAY['merchant_admin'])
    )
    WITH CHECK (
        merchant_id = public.current_active_merchant_id()
        AND public.has_merchant_role(merchant_id, ARRAY['merchant_admin'])
    );

-- API Keys: Only Admin can view and manage
CREATE POLICY p_api_keys_select ON public.merchant_api_keys
    FOR SELECT
    TO authenticated
    USING (
        merchant_id = public.current_active_merchant_id()
        AND public.has_merchant_role(merchant_id, ARRAY['merchant_admin'])
    );

CREATE POLICY p_api_keys_admin_manage ON public.merchant_api_keys
    FOR ALL
    TO authenticated
    USING (
        merchant_id = public.current_active_merchant_id()
        AND public.has_merchant_role(merchant_id, ARRAY['merchant_admin'])
    )
    WITH CHECK (
        merchant_id = public.current_active_merchant_id()
        AND public.has_merchant_role(merchant_id, ARRAY['merchant_admin'])
    );


-- ==============================================================================
-- 5. RLS POLICIES: CUSTOMERS & TRANSACTIONS
-- ==============================================================================

CREATE POLICY p_customers_select ON public.customers
    FOR SELECT
    TO authenticated
    USING (
        merchant_id = public.current_active_merchant_id()
        AND public.has_merchant_role(merchant_id, ARRAY['merchant_admin', 'recovery_operator', 'risk_officer', 'auditor'])
    );

CREATE POLICY p_customers_manage ON public.customers
    FOR ALL
    TO authenticated
    USING (
        merchant_id = public.current_active_merchant_id()
        AND public.has_merchant_role(merchant_id, ARRAY['merchant_admin', 'system_service'])
    )
    WITH CHECK (
        merchant_id = public.current_active_merchant_id()
        AND public.has_merchant_role(merchant_id, ARRAY['merchant_admin', 'system_service'])
    );

-- Transactions: Selectable by tenant team; inserted by admin/service
CREATE POLICY p_transactions_select ON public.transactions
    FOR SELECT
    TO authenticated
    USING (
        merchant_id = public.current_active_merchant_id()
        AND public.has_merchant_role(merchant_id, ARRAY['merchant_admin', 'recovery_operator', 'risk_officer', 'auditor'])
    );

CREATE POLICY p_transactions_insert ON public.transactions
    FOR INSERT
    TO authenticated
    WITH CHECK (
        merchant_id = public.current_active_merchant_id()
        AND public.has_merchant_role(merchant_id, ARRAY['merchant_admin', 'recovery_operator', 'system_service'])
    );

CREATE POLICY p_transactions_update ON public.transactions
    FOR UPDATE
    TO authenticated
    USING (
        merchant_id = public.current_active_merchant_id()
        AND public.has_merchant_role(merchant_id, ARRAY['merchant_admin', 'recovery_operator', 'system_service'])
    )
    WITH CHECK (
        merchant_id = public.current_active_merchant_id()
        AND public.has_merchant_role(merchant_id, ARRAY['merchant_admin', 'recovery_operator', 'system_service'])
    );


-- ==============================================================================
-- 6. RLS POLICIES: MODEL VERSIONS (Global Read, System Manage)
-- ==============================================================================

CREATE POLICY p_model_versions_select ON public.model_versions
    FOR SELECT
    TO authenticated
    USING (true); -- Publicly viewable by all authenticated operators


-- ==============================================================================
-- 7. RLS POLICIES: CAUSAL DECISIONS
-- ==============================================================================

CREATE POLICY p_decisions_select ON public.causal_decisions
    FOR SELECT
    TO authenticated
    USING (
        merchant_id = public.current_active_merchant_id()
        AND public.has_merchant_role(merchant_id, ARRAY['merchant_admin', 'recovery_operator', 'risk_officer', 'auditor'])
    );

CREATE POLICY p_decisions_insert ON public.causal_decisions
    FOR INSERT
    TO authenticated
    WITH CHECK (
        merchant_id = public.current_active_merchant_id()
        AND public.has_merchant_role(merchant_id, ARRAY['merchant_admin', 'recovery_operator', 'system_service'])
    );

CREATE POLICY p_decisions_update ON public.causal_decisions
    FOR UPDATE
    TO authenticated
    USING (
        merchant_id = public.current_active_merchant_id()
        AND public.has_merchant_role(merchant_id, ARRAY['merchant_admin', 'recovery_operator', 'system_service'])
    )
    WITH CHECK (
        merchant_id = public.current_active_merchant_id()
        AND public.has_merchant_role(merchant_id, ARRAY['merchant_admin', 'recovery_operator', 'system_service'])
    );


-- ==============================================================================
-- 8. RLS POLICIES: WEBHOOK INBOX & IDEMPOTENCY
-- ==============================================================================

CREATE POLICY p_webhook_inbox_select ON public.webhook_inbox
    FOR SELECT
    TO authenticated
    USING (
        merchant_id IS NULL OR (
            merchant_id = public.current_active_merchant_id()
            AND public.has_merchant_role(merchant_id, ARRAY['merchant_admin', 'recovery_operator', 'auditor'])
        )
    );

CREATE POLICY p_idempotency_select ON public.idempotency_keys
    FOR SELECT
    TO authenticated
    USING (
        merchant_id = public.current_active_merchant_id()
        AND public.has_merchant_role(merchant_id, ARRAY['merchant_admin', 'recovery_operator', 'system_service'])
    );

CREATE POLICY p_idempotency_manage ON public.idempotency_keys
    FOR ALL
    TO authenticated
    USING (
        merchant_id = public.current_active_merchant_id()
        AND public.has_merchant_role(merchant_id, ARRAY['merchant_admin', 'system_service'])
    )
    WITH CHECK (
        merchant_id = public.current_active_merchant_id()
        AND public.has_merchant_role(merchant_id, ARRAY['merchant_admin', 'system_service'])
    );


-- ==============================================================================
-- 9. RLS POLICIES: RECOVERY OUTBOX & DISPATCHES
-- ==============================================================================

CREATE POLICY p_outbox_select ON public.recovery_outbox
    FOR SELECT
    TO authenticated
    USING (
        merchant_id = public.current_active_merchant_id()
        AND public.has_merchant_role(merchant_id, ARRAY['merchant_admin', 'recovery_operator', 'auditor'])
    );

CREATE POLICY p_outbox_manage ON public.recovery_outbox
    FOR ALL
    TO authenticated
    USING (
        merchant_id = public.current_active_merchant_id()
        AND public.has_merchant_role(merchant_id, ARRAY['merchant_admin', 'recovery_operator', 'system_service'])
    )
    WITH CHECK (
        merchant_id = public.current_active_merchant_id()
        AND public.has_merchant_role(merchant_id, ARRAY['merchant_admin', 'recovery_operator', 'system_service'])
    );

CREATE POLICY p_dispatches_select ON public.recovery_dispatches
    FOR SELECT
    TO authenticated
    USING (
        merchant_id = public.current_active_merchant_id()
        AND public.has_merchant_role(merchant_id, ARRAY['merchant_admin', 'recovery_operator', 'risk_officer', 'auditor'])
    );

CREATE POLICY p_dispatches_insert ON public.recovery_dispatches
    FOR INSERT
    TO authenticated
    WITH CHECK (
        merchant_id = public.current_active_merchant_id()
        AND public.has_merchant_role(merchant_id, ARRAY['merchant_admin', 'recovery_operator', 'system_service'])
    );


-- ==============================================================================
-- 10. RLS POLICIES: PAYMENT OUTCOMES
-- ==============================================================================

CREATE POLICY p_outcomes_select ON public.payment_outcomes
    FOR SELECT
    TO authenticated
    USING (
        merchant_id = public.current_active_merchant_id()
        AND public.has_merchant_role(merchant_id, ARRAY['merchant_admin', 'recovery_operator', 'risk_officer', 'auditor'])
    );

CREATE POLICY p_outcomes_manage ON public.payment_outcomes
    FOR ALL
    TO authenticated
    USING (
        merchant_id = public.current_active_merchant_id()
        AND public.has_merchant_role(merchant_id, ARRAY['merchant_admin', 'system_service'])
    )
    WITH CHECK (
        merchant_id = public.current_active_merchant_id()
        AND public.has_merchant_role(merchant_id, ARRAY['merchant_admin', 'system_service'])
    );


-- ==============================================================================
-- 11. RLS POLICIES: AUDIT LEDGER BLOCKS (Strict Append-Only Immutability)
-- ==============================================================================

-- Select: Tenant team & auditors can inspect
CREATE POLICY p_audit_blocks_select ON public.audit_ledger_blocks
    FOR SELECT
    TO authenticated
    USING (
        merchant_id IS NULL OR (
            merchant_id = public.current_active_merchant_id()
            AND public.has_merchant_role(merchant_id, ARRAY['merchant_admin', 'recovery_operator', 'risk_officer', 'auditor'])
        )
    );

-- Insert: Only Admin / System service can append blocks
CREATE POLICY p_audit_blocks_insert ON public.audit_ledger_blocks
    FOR INSERT
    TO authenticated
    WITH CHECK (
        merchant_id IS NULL OR (
            merchant_id = public.current_active_merchant_id()
            AND public.has_merchant_role(merchant_id, ARRAY['merchant_admin', 'system_service'])
        )
    );

-- Update: FORBIDDEN for all roles (Zero updates allowed on cryptographic ledger)
CREATE POLICY p_audit_blocks_update_forbidden ON public.audit_ledger_blocks
    FOR UPDATE
    TO authenticated
    USING (false);

-- Delete: FORBIDDEN for all roles (Zero deletions allowed on cryptographic ledger)
CREATE POLICY p_audit_blocks_delete_forbidden ON public.audit_ledger_blocks
    FOR DELETE
    TO authenticated
    USING (false);

-- Cryptographic Immutability Trigger (Database-Level Tamper Prevention)
CREATE OR REPLACE FUNCTION public.prevent_audit_ledger_tampering()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    RAISE EXCEPTION 'AuditLedger is an immutable append-only cryptographic ledger. Updates and deletions are strictly forbidden by protocol.';
END;
$$;

DROP TRIGGER IF EXISTS trg_audit_ledger_immutability ON public.audit_ledger_blocks;
CREATE TRIGGER trg_audit_ledger_immutability
    BEFORE UPDATE OR DELETE ON public.audit_ledger_blocks
    FOR EACH ROW
    EXECUTE FUNCTION public.prevent_audit_ledger_tampering();


-- ==============================================================================
-- 12. RLS POLICIES: BANDIT WEIGHTS
-- ==============================================================================

CREATE POLICY p_bandit_weights_select ON public.bandit_weights
    FOR SELECT
    TO authenticated
    USING (
        merchant_id = public.current_active_merchant_id()
        AND public.has_merchant_role(merchant_id, ARRAY['merchant_admin', 'recovery_operator', 'risk_officer'])
    );

CREATE POLICY p_bandit_weights_manage ON public.bandit_weights
    FOR ALL
    TO authenticated
    USING (
        merchant_id = public.current_active_merchant_id()
        AND public.has_merchant_role(merchant_id, ARRAY['merchant_admin', 'system_service'])
    )
    WITH CHECK (
        merchant_id = public.current_active_merchant_id()
        AND public.has_merchant_role(merchant_id, ARRAY['merchant_admin', 'system_service'])
    );

