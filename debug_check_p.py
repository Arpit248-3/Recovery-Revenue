import sys, os
sys.path.insert(0, r"C:\Users\arpit\Desktop\Razorpay\Razorpay")
from dotenv import load_dotenv
load_dotenv(r"C:\Users\arpit\Desktop\Razorpay\Razorpay\.env")
from wapsi.recovery.case_store import get_durable_case_store

store = get_durable_case_store()
c1 = store.get_case_by_payment_id("pay_TwOvLtaM0gFg5w")
print("c1:", c1)
c2 = store.get_case_by_payment_id("pay_TwOzVUUtGrWWjp")
print("c2:", c2)

