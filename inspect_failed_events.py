import urllib.request, json, base64

req = urllib.request.Request("http://127.0.0.1:4040/api/requests/http?limit=50")
res = json.loads(urllib.request.urlopen(req).read())
for r in res["requests"]:
    det_req = urllib.request.Request(f"http://127.0.0.1:4040/api/requests/http/{r['id']}")
    det = json.loads(urllib.request.urlopen(det_req).read())
    raw = base64.b64decode(det["request"]["raw"]).decode("utf-8", errors="ignore")
    if "pay_TwOzVUUtGrWWjp" in raw or "pay_TwOvLtaM0gFg5w" in raw:
        print(f"--- Found {r['id']} ---")
        print("Status:", r["response"]["status_code"])
        resp_raw = base64.b64decode(det["response"]["raw"]).decode("utf-8", errors="ignore")
        print("Response:", resp_raw)

