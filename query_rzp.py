import sqlite3

conn = sqlite3.connect(r"C:\Users\arpit\Desktop\Razorpay\Razorpay\.wapsi_data\recovery_cases.db")
conn.row_factory = sqlite3.Row
rows = conn.execute("SELECT case_id, updated_at_utc, created_at_utc FROM recovery_cases WHERE case_id LIKE '%RZP%'").fetchall()
for r in rows:
    print(r["case_id"], r["updated_at_utc"], r["created_at_utc"])
