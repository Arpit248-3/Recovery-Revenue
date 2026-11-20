import sqlite3

conn = sqlite3.connect(r"C:\Users\arpit\Desktop\Razorpay\Razorpay\.wapsi_data\recovery_cases.db")
conn.row_factory = sqlite3.Row
rows = conn.execute("SELECT case_id, customer_name, amount_paise, payment_id, status, created_at_utc FROM recovery_cases ORDER BY updated_at_utc DESC").fetchall()
print(f"Total SQLite cases: {len(rows)}")
for r in rows:
    print(f"{r['case_id']} | {r['customer_name']} | Rs {r['amount_paise']/100:.2f} | {r['payment_id']} | {r['status']}")
conn.close()

