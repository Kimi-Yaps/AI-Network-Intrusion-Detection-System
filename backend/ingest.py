import json
import os
from pathlib import Path
import time
import urllib.request
import yaml

SYSTEM_CONFIG_PATH = Path(os.environ.get("NADS_CONFIG_PATH", "/etc/nads/config.yaml"))
FALLBACK_CONFIG_PATH = Path(__file__).resolve().parent / "config.yaml"


def load_config():
    path = SYSTEM_CONFIG_PATH if SYSTEM_CONFIG_PATH.exists() else FALLBACK_CONFIG_PATH
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def follow(path: str):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def forward_event(api_base: str, event: dict):
    req = urllib.request.Request(
        f"{api_base.rstrip('/')}/api/events",
        data=json.dumps(event).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status
    except Exception as exc:
        print(f"[nads-ingest] Failed to forward event: {exc}")
        return None


if __name__ == "__main__":
    cfg = load_config()
    eve_path = cfg["monitoring"]["suricata_eve_path"]
    backend_url = os.environ.get("NADS_BACKEND_URL", "http://127.0.0.1:8000")
    print(f"[nads-ingest] Tailing {eve_path} -> {backend_url}/api/events")
    for suricata_event in follow(eve_path):
        forward_event(backend_url, suricata_event)

