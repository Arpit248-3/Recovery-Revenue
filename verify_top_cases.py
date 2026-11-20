import urllib.request, json

req = urllib.request.Request('http://localhost:8000/api/v1/recovery/cases', headers={'X-API-Key':'rzp_test_wapsi_key_2026'})
res = json.loads(urllib.request.urlopen(req).read())
cases = res['cases']
print('Total cases:', len(cases))
for i, c in enumerate(cases[:8]):
    print(f"#{i+1} {c.get('caseId')} | {c.get('customerName')} | Rs {c.get('amount')} | Status: {c.get('status')} | Live: {c.get('isLive')} | Link: {c.get('paymentLinkUrl')}")

