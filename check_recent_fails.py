import sqlite3

conn = sqlite3.connect(r"C:\Users\arpit\Desktop\Razorpay\Razorpay\.wapsi_data\recovery_cases.db")
conn.row_factory = sqlite3.Row
rows = conn.execute("SELECT case_id, customer_name, amount_paise, payment_id, status FROM recovery_cases WHERE payment_id IN ('pay_TwOzVUUtGrWWjp', 'pay_TwOvLtaM0gFg5w', 'pay_TwOfVqAxMnammY')").fetchall()
print(f"Matching cases in DB: {len(rows)}")
for r in rows:
    print(f"Case: {r['case_id']} | Payment: {r['payment_id']} | Name: {r['customer_name']} | Amount: Rs {r['amount_paise']/100:.2f}")
conn.close()

