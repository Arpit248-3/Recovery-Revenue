"""
Comprehensive Verification Suite for Razorpay Authentication in WAPSI.
Runs all 5 tests required by the specification:
1. WapsiSettings configuration test.
2. RazorpayClient credential-loading test.
3. Exact payment_links endpoint connectivity test.
4. Synthetic Lab health-check test against running backend.
5. Frontend provider-health proxy test against running Vite frontend.
"""

from __future__ import annotations

import sys
import httpx
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from wapsi.core.config import get_settings, reset_settings, WapsiSettings
from wapsi.integrations.razorpay.client import RazorpayClient


def mask_suffix(val: str | None) -> str:
    if not val:
        return "<EMPTY>"
    return f"****{str(val).strip()[-4:]}"


def test_1_wapsisettings_configuration():
    print("[TEST 1] WapsiSettings Configuration Test")
    reset_settings()
    settings = get_settings()
    assert settings.razorpay_mode == "test", f"Expected 'test', got '{settings.razorpay_mode}'"
    assert settings.razorpay_key_id is not None, "razorpay_key_id should not be None"
    assert settings.razorpay_key_id.startswith("rzp_test_"), "razorpay_key_id must start with rzp_test_"
    assert settings.razorpay_key_secret is not None, "razorpay_key_secret should not be None"
    assert settings.masked_key_id.endswith("hbyW"), f"Expected suffix 'hbyW', got '{settings.masked_key_id}'"
    print(f"  -> PASS: Mode={settings.razorpay_mode}, MaskedKey={settings.masked_key_id}, HasSecret={settings.has_key_secret}")


def test_2_razorpayclient_credential_loading():
    print("[TEST 2] RazorpayClient Credential-Loading Test")
    client = RazorpayClient()
    assert client.key_id is not None, "RazorpayClient key_id must be populated"
    assert client.key_id.startswith("rzp_test_"), "RazorpayClient key_id must be test mode"
    assert client.key_id.endswith("hbyW"), f"Expected client key ending in 'hbyW', got {mask_suffix(client.key_id)}"
    assert client.key_secret is not None, "RazorpayClient key_secret must be populated"
    print(f"  -> PASS: RazorpayClient loaded Key ID: {mask_suffix(client.key_id)}")


def test_3_exact_payment_links_connectivity():
    print("[TEST 3] Exact payment_links Endpoint Connectivity Test")
    client = RazorpayClient()
    # GET /payment_links?count=1
    res = client._request_sync("GET", "/payment_links", params={"count": 1})
    assert isinstance(res, dict), "Response should be a dict"
    assert "payment_links" in res or "items" in res or "entity" in res, f"Expected standard collection response, got {res.keys()}"
    print(f"  -> PASS: HTTP 200 OK from api.razorpay.com/v1/payment_links?count=1 (entity={res.get('entity')})")


def test_4_synthetic_lab_health_check():
    print("[TEST 4] Synthetic Lab Health-Check Test (Backend Port 8000)")
    resp = httpx.get("http://127.0.0.1:8000/api/v1/integrations/health", timeout=30.0)
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
    data = resp.json()
    rzp = data.get("services", {}).get("razorpay", {})
    assert rzp.get("status") == "connected", f"Expected 'connected', got '{rzp.get('status')}'"
    assert rzp.get("masked_key_id") == "rzp_test_****hbyW", f"Expected 'rzp_test_****hbyW', got '{rzp.get('masked_key_id')}'"
    assert rzp.get("mode") == "test", f"Expected 'test', got '{rzp.get('mode')}'"
    print(f"  -> PASS: Backend reports status={rzp.get('status')}, masked_key_id={rzp.get('masked_key_id')}")


def test_5_frontend_provider_health_proxy():
    print("[TEST 5] Frontend Provider-Health Proxy Test (Vite Port 5173)")
    resp = httpx.get("http://localhost:5173/api/v1/integrations/health", timeout=30.0)
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
    data = resp.json()
    rzp = data.get("services", {}).get("razorpay", {})
    assert rzp.get("status") == "connected", f"Expected 'connected', got '{rzp.get('status')}'"
    assert rzp.get("masked_key_id") == "rzp_test_****hbyW", f"Expected 'rzp_test_****hbyW', got '{rzp.get('masked_key_id')}'"
    print(f"  -> PASS: Vite proxy reports status={rzp.get('status')}, masked_key_id={rzp.get('masked_key_id')}")


def main():
    print("=" * 70)
    print("RUNNING 5-POINT VERIFICATION SUITE")
    print("=" * 70)
    try:
        test_1_wapsisettings_configuration()
        test_2_razorpayclient_credential_loading()
        test_3_exact_payment_links_connectivity()
        test_4_synthetic_lab_health_check()
        test_5_frontend_provider_health_proxy()
        print("=" * 70)
        print("ALL 5 VERIFICATION CHECKS PASSED PERFECTLY!")
        print("=" * 70)
    except AssertionError as e:
        print(f"[FAIL] Assertion error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[FAIL] Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
