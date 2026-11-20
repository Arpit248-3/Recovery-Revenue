import os, sys
sys.path.insert(0, r"C:\Users\arpit\Desktop\Razorpay\Razorpay")
from dotenv import load_dotenv
load_dotenv(r"C:\Users\arpit\Desktop\Razorpay\Razorpay\.env")
from wapsi.recovery.case_store import get_durable_case_store

store = get_durable_case_store()
print("Store is_postgres:", store.is_postgres)
cases, total = store.list_cases(limit=100)
print(f"Total durable cases: {total}")
for c in cases[:10]:
    print(f"ID: {c.case_id} | Name: {c.customer_name} | Amount: Rs {c.amount_paise/100:.2f} | Status: {c.status} | Created: {c.created_at_utc} | Link: {c.payment_link_url}")
