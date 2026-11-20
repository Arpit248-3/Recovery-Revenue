import urllib.request, json, base64

req = urllib.request.Request("http://127.0.0.1:4040/api/requests/http?limit=50")
res = json.loads(urllib.request.urlopen(req).read())
print(f"Total requests: {len(res['requests'])}")
for r in res["requests"]:
    uri = r["request"]["uri"]
    if "webhooks/razorpay" in uri:
        det_req = urllib.request.Request(f"http://127.0.0.1:4040/api/requests/http/{r['id']}")
        det = json.loads(urllib.request.urlopen(det_req).read())
        raw = base64.b64decode(det["request"]["raw"]).decode("utf-8", errors="ignore")
        body = raw.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in raw else ""
        if body:
            try:
                payload = json.loads(body)
                event = payload.get("event")
                entity = payload.get("payload", {}).get("payment", {}).get("entity", {})
                pl_entity = payload.get("payload", {}).get("payment_link", {}).get("entity", {})
                print(f"Event: {event} | Status: {r['response']['status_code']} | Pay ID: {entity.get('id')} | Order ID: {entity.get('order_id')} | PL ID: {pl_entity.get('id')} | Desc: {entity.get('description') or pl_entity.get('description')}")
            except Exception as e:
                print("JSON error:", e)
