import sqlite3, os

db1 = r"C:\Users\arpit\Desktop\Razorpay\.wapsi_data\recovery_cases.db"
db2 = r"C:\Users\arpit\Desktop\Razorpay\Razorpay\.wapsi_data\recovery_cases.db"

if os.path.exists(db1) and os.path.exists(db2):
    conn1 = sqlite3.connect(db1)
    conn1.row_factory = sqlite3.Row
    rows1 = conn1.execute("SELECT * FROM recovery_cases").fetchall()
    
    conn2 = sqlite3.connect(db2)
    for r in rows1:
        cols = list(r.keys())
        placeholders = ", ".join(["?"] * len(cols))
        col_names = ", ".join(cols)
        conn2.execute(f"INSERT OR REPLACE INTO recovery_cases ({col_names}) VALUES ({placeholders})", tuple(r))
    conn2.commit()
    print(f"Merged {len(rows1)} cases from parent DB into canonical DB.")
    conn1.close()
    conn2.close()

