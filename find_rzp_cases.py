import urllib.request, json

req = urllib.request.Request('http://localhost:8000/api/v1/recovery/cases?limit=100', headers={'X-API-Key':'rzp_test_wapsi_key_2026'})
res = json.loads(urllib.request.urlopen(req).read())
cases = res['cases']
rzp_cases = [c for c in cases if "RZP" in c.get('caseId', '') or "Uz0C1jE" in c.get('caseId', '') or "2500" in str(c.get('amount', ''))]
print(f"Total matching RZP cases: {len(rzp_cases)}")
for c in rzp_cases:
    print(c.get('caseId'), c.get('customerName'), c.get('amount'), c.get('paymentLinkId'), c.get('paymentLinkUrl'))

