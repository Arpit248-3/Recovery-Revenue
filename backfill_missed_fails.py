import sys, os, time, json
sys.path.insert(0, r"C:\Users\arpit\Desktop\Razorpay\Razorpay")
from dotenv import load_dotenv
load_dotenv(r"C:\Users\arpit\Desktop\Razorpay\Razorpay\.env")

from wapsi.recovery.case_store import get_durable_case_store
from wapsi.recovery.engine import get_recovery_engine
from wapsi.api.frontend_adapter import active_cases_store, case_details_store, generate_decision_output_for_case

store = get_durable_case_store()
engine = get_recovery_engine()

# Ingest pay_TwOvLtaM0gFg5w
p1 = "pay_TwOvLtaM0gFg5w"
if not store.get_case_by_payment_id(p1):
    c1 = engine.create_case(
        case_id="RX-RZP-Uz0C1jE-2",
        payment_id=p1,
        amount_paise=250000,
        customer_phone="+916260055671",
        customer_name="Arpit (Razorpay Test #2)",
        merchant_name="Merchant",
        merchant_id="04a2aaf8-8c8a-4d99-852c-cefc80e82019",
        error_code="BAD_REQUEST_ERROR",
        error_category="FRICTION_OTP_UX",
        max_attempts=3,
    )
    c1.payment_link_id = "plink_Uz0C1jE"
    c1.payment_link_url = "https://rzp.io/rzp/Uz0C1jE"
    c1.decision_metadata = {
        "incrementalUplift": 0.38,
        "naturalRecoveryProbability": 0.12,
        "treatmentProbability": 0.72,
        "recommendedAction": "WHATSAPP",
        "recommendedActionLabel": "WhatsApp 1-Click Link",
        "optimalWindow": "Next 15m (Optimal Peak)",
        "failureCode": "BAD_REQUEST_ERROR",
        "failureReason": "Payment declined by issuing bank (Test Failure)",
        "domain": "CHECKOUT",
        "customerHandle": "+916260055671",
    }
    store.save_case(c1)
    print("Ingested pay_TwOvLtaM0gFg5w as RX-RZP-Uz0C1jE-2")

# Ingest pay_TwOzVUUtGrWWjp
p2 = "pay_TwOzVUUtGrWWjp"
if not store.get_case_by_payment_id(p2):
    c2 = engine.create_case(
        case_id="RX-RZP-TwOzVU",
        payment_id=p2,
        amount_paise=250000,
        customer_phone="+916260055671",
        customer_name="Arpit (Razorpay Test #3)",
        merchant_name="Merchant",
        merchant_id="04a2aaf8-8c8a-4d99-852c-cefc80e82019",
        error_code="BAD_REQUEST_ERROR",
        error_category="FRICTION_OTP_UX",
        max_attempts=3,
    )
    c2.decision_metadata = {
        "incrementalUplift": 0.38,
        "naturalRecoveryProbability": 0.12,
        "treatmentProbability": 0.72,
        "recommendedAction": "WHATSAPP",
        "recommendedActionLabel": "WhatsApp 1-Click Link",
        "optimalWindow": "Next 15m (Optimal Peak)",
        "failureCode": "BAD_REQUEST_ERROR",
        "failureReason": "Bank decline / OTP timeout",
        "domain": "CHECKOUT",
        "customerHandle": "+916260055671",
    }
    store.save_case(c2)
    print("Ingested pay_TwOzVUUtGrWWjp as RX-RZP-TwOzVU")

print("Done backfilling missed test failures!")

