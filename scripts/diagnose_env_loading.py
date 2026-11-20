import os
import sys
import winreg
from pathlib import Path

def mask(val: str | None) -> str:
    if not val:
        return "<NOT_SET>"
    val = str(val).strip()
    if len(val) <= 8:
        return "****"
    return f"{val[:8]}...{val[-4:]}"

def mask_suffix(val: str | None) -> str:
    if not val:
        return "<NOT_SET>"
    val = str(val).strip()
    if len(val) < 4:
        return "****"
    return f"****{val[-4:]}"

def main():
    print("=== SAFE CONFIGURATION DIAGNOSTICS ===")
    print(f"Current Python executable: {sys.executable}")
    print(f"Current process ID: {os.getpid()}")
    print(f"Current working directory: {os.getcwd()}")

    # Project root from this script
    script_path = Path(__file__).resolve()
    project_root = script_path.parent.parent
    expected_env = project_root / ".env"
    print(f"Absolute .env path expected: {expected_env}")
    print(f"Whether .env exists: {expected_env.exists()}")

    # Read .env directly
    env_file_key = None
    env_file_secret = None
    env_file_mode = None
    if expected_env.exists():
        for line in expected_env.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line.startswith("RAZORPAY_KEY_ID="):
                env_file_key = line.split("=", 1)[1].strip().strip("'\"")
            elif line.startswith("RAZORPAY_KEY_SECRET="):
                env_file_secret = line.split("=", 1)[1].strip().strip("'\"")
            elif line.startswith("RAZORPAY_MODE="):
                env_file_mode = line.split("=", 1)[1].strip().strip("'\"")

    print(f"Mode in .env: {env_file_mode}")
    print(f"Key ID in .env exists: {bool(env_file_key)}")
    print(f"Masked Key ID in .env: {mask(env_file_key)} (suffix: {mask_suffix(env_file_key)})")
    print(f"Key Secret in .env exists: {bool(env_file_secret)}")

    # Check process-level environment variables
    proc_key = os.environ.get("RAZORPAY_KEY_ID")
    proc_secret = os.environ.get("RAZORPAY_KEY_SECRET")
    print(f"Process os.environ Key ID exists: {bool(proc_key)}")
    print(f"Process os.environ Masked Key ID: {mask(proc_key)} (suffix: {mask_suffix(proc_key)})")
    print(f"Process os.environ Key Secret exists: {bool(proc_secret)}")
    print(f"Process-level env vars override .env: {bool(proc_key and proc_key != env_file_key)}")

    # Check Windows Registry
    reg_key = None
    reg_secret = None
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Environment") as key:
            try:
                reg_key, _ = winreg.QueryValueEx(key, "RAZORPAY_KEY_ID")
            except FileNotFoundError:
                reg_key = None
            try:
                reg_secret, _ = winreg.QueryValueEx(key, "RAZORPAY_KEY_SECRET")
            except FileNotFoundError:
                reg_secret = None
    except Exception as e:
        print(f"Windows Registry check failed: {e}")

    print(f"Windows Registry Key ID exists: {bool(reg_key)}")
    print(f"Windows Registry Masked Key ID: {mask(reg_key)} (suffix: {mask_suffix(reg_key)})")
    print(f"Windows Registry Key Secret exists: {bool(reg_secret)}")
    print(f"Windows registry fallback affecting configuration: {bool(reg_key and reg_key != env_file_key)}")

    # Test WapsiSettings loading
    sys.path.insert(0, str(project_root))
    from wapsi.core.config import WapsiSettings, get_settings
    settings = WapsiSettings()
    print(f"WapsiSettings razorpay_mode: {settings.razorpay_mode}")
    print(f"WapsiSettings Key ID exists: {bool(settings.razorpay_key_id)}")
    print(f"WapsiSettings Masked Key ID: {settings.masked_key_id}")
    print(f"WapsiSettings Key Secret exists: {settings.has_key_secret}")

    from wapsi.integrations.razorpay.client import RazorpayClient
    client = RazorpayClient()
    print(f"RazorpayClient Key ID exists: {bool(client.key_id)}")
    print(f"RazorpayClient Masked Key ID: {mask(client.key_id)}")
    print(f"RazorpayClient uses same settings instance: {client.key_id == settings.razorpay_key_id}")

if __name__ == "__main__":
    main()
