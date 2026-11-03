import asyncio
from collections import defaultdict, deque
from contextlib import asynccontextmanager
import json
import math
import os
from pathlib import Path
import time
from typing import Any
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import yaml

# Load .env from project root or backend directory
BASE_DIR = Path(__file__).resolve().parent
ROOT_DIR = BASE_DIR.parent
load_dotenv(ROOT_DIR / ".env")
load_dotenv(BASE_DIR / ".env")

SYSTEM_CONFIG_PATH = Path(os.environ.get("NADS_CONFIG_PATH", "/etc/nads/config.yaml"))
FALLBACK_CONFIG_PATH = BASE_DIR / "config.yaml"


def resolve_config_path() -> Path:
    if SYSTEM_CONFIG_PATH.exists():
        return SYSTEM_CONFIG_PATH
    return FALLBACK_CONFIG_PATH


def load_config() -> tuple[dict[str, Any], str]:
    path = resolve_config_path()
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data, str(path)


config, active_config_path = load_config()

alerts: deque[dict[str, Any]] = deque(maxlen=1000)
dns_counts: dict[str, deque[float]] = defaultdict(deque)
nxdomain_counts: dict[str, deque[float]] = defaultdict(deque)
recent_dns_queries: deque[dict[str, Any]] = deque(maxlen=250)


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    freq: dict[str, int] = defaultdict(int)
    for ch in value:
        freq[ch] += 1
    total = len(value)
    return -sum((n / total) * math.log2(n / total) for n in freq.values())


def add_alert(
    severity: str,
    category: str,
    source_ip: str,
    summary: str,
    evidence: dict[str, Any],
) -> dict[str, Any]:
    alert = {
        "id": f"{time.time_ns()}",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "severity": severity,
        "category": category,
        "source_ip": source_ip,
        "summary": summary,
        "evidence": evidence,
    }
    alerts.appendleft(alert)
    return alert


def process_suricata_event(event: dict[str, Any]) -> list[dict[str, Any]]:
    created_alerts: list[dict[str, Any]] = []
    event_type = event.get("event_type")

    if event_type == "alert":
        src = event.get("src_ip", "unknown")
        signature = event.get("alert", {}).get("signature", "Unknown alert")
        severity_num = event.get("alert", {}).get("severity", 3)
        created_alerts.append(
            add_alert(
                severity="high" if severity_num <= 2 else "medium",
                category="IDS signature",
                source_ip=src,
                summary=signature,
                evidence=event,
            )
        )

    elif event_type == "dns":
        dns_data = event.get("dns", {})
        src = event.get("src_ip", "unknown")
        qname = str(dns_data.get("rrname", "")).rstrip(".")
        rcode = dns_data.get("rcode")
        rrtype = dns_data.get("rrtype", "A")
        now = time.time()

        dq = dns_counts[src]
        dq.append(now)
        while dq and now - dq[0] > 60:
            dq.popleft()

        labels = qname.split(".") if qname else []
        subdomain = ".".join(labels[:-2]) if len(labels) >= 3 else ""
        entropy = round(shannon_entropy(subdomain), 2)
        tld = labels[-1].lower() if len(labels) >= 2 else ""

        recent_dns_queries.appendleft(
            {
                "id": f"dns-{time.time_ns()}",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                "source_ip": src,
                "rrname": qname,
                "rrtype": rrtype,
                "rcode": rcode,
                "entropy": entropy,
                "qpm_for_client": len(dq),
            }
        )

        max_qpm = config["dns_anomaly"]["max_queries_per_client_per_minute"]
        if len(dq) > max_qpm:
            created_alerts.append(
                add_alert(
                    severity="high",
                    category="DNS volume",
                    source_ip=src,
                    summary=f"High DNS query volume: {len(dq)} queries/minute (threshold: {max_qpm})",
                    evidence={"query": qname, "queries_per_minute": len(dq)},
                )
            )

        if rcode == 3 or str(rcode).upper() == "NXDOMAIN":
            nx = nxdomain_counts[src]
            nx.append(now)
            while nx and now - nx[0] > 300:
                nx.popleft()

            nx_ratio = len(nx) / max(len(dq), 1)
            if len(nx) >= 20 or (
                len(dq) >= 10 and nx_ratio >= config["dns_anomaly"]["max_nxdomain_ratio"]
            ):
                created_alerts.append(
                    add_alert(
                        severity="medium",
                        category="Possible DGA",
                        source_ip=src,
                        summary=f"Repeated NXDOMAIN responses from {src} ({len(nx)} in 5m)",
                        evidence={
                            "recent_nxdomain": len(nx),
                            "nxdomain_ratio": round(nx_ratio, 2),
                            "query": qname,
                        },
                    )
                )

        if len(labels) >= 3:
            if entropy > config["dns_anomaly"]["high_entropy_threshold"]:
                created_alerts.append(
                    add_alert(
                        severity="high",
                        category="Possible DNS tunneling",
                        source_ip=src,
                        summary=f"High-entropy DNS label ({entropy} bits): {qname}",
                        evidence={
                            "entropy": entropy,
                            "subdomain": subdomain,
                            "query": qname,
                            "rrtype": rrtype,
                        },
                    )
                )

        suspicious_tlds = [
            str(t).lower().lstrip(".")
            for t in config["dns_anomaly"].get("suspicious_tlds", [])
        ]
        if tld and tld in suspicious_tlds:
            created_alerts.append(
                add_alert(
                    severity="medium",
                    category="Suspicious TLD",
                    source_ip=src,
                    summary=f"Query to monitored suspicious TLD (.{tld}): {qname}",
                    evidence={"tld": tld, "query": qname, "rrtype": rrtype},
                )
            )

    return created_alerts


def seed_initial_events() -> None:
    """Seeds initial demonstration telemetry if no live Suricata alerts have arrived yet."""
    if alerts:
        return
    sample_events = [
        {
            "event_type": "dns",
            "src_ip": "10.0.14.88",
            "dns": {
                "rrname": "4f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c.x91k2m.c2-tunnel.net",
                "rrtype": "TXT",
                "rcode": 0,
            },
        },
        {
            "event_type": "dns",
            "src_ip": "10.0.14.23",
            "dns": {
                "rrname": " invoice-update-auth-portal.zip",
                "rrtype": "A",
                "rcode": 0,
            },
        },
        {
            "event_type": "alert",
            "src_ip": "198.51.100.42",
            "dest_ip": config["server"]["public_ip"],
            "proto": "TCP",
            "alert": {
                "signature": "ET WEB_SERVER SQL Injection Attempt in URI (UNION SELECT)",
                "category": "Web Application Attack",
                "severity": 1,
            },
        },
        {
            "event_type": "alert",
            "src_ip": "192.0.2.199",
            "dest_ip": config["server"]["public_ip"],
            "proto": "TCP",
            "alert": {
                "signature": "ET SCAN Nmap Scripting Engine User-Agent Detected",
                "category": "Attempted Information Leak",
                "severity": 2,
            },
        },
    ]
    for ev in sample_events:
        process_suricata_event(ev)


async def tail_suricata_log_task() -> None:
    """Background task that tails /var/log/suricata/eve.json when available on Ubuntu."""
    eve_path = Path(config["monitoring"]["suricata_eve_path"])
    poll_interval = float(config["monitoring"].get("poll_interval_seconds", 2))
    while True:
        if eve_path.exists():
            try:
                with open(eve_path, "r", encoding="utf-8", errors="replace") as f:
                    f.seek(0, os.SEEK_END)
                    while True:
                        line = f.readline()
                        if not line:
                            await asyncio.sleep(0.5)
                            continue
                        try:
                            event = json.loads(line)
                            process_suricata_event(event)
                        except json.JSONDecodeError:
                            continue
            except Exception:
                await asyncio.sleep(poll_interval)
        else:
            await asyncio.sleep(poll_interval)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    seed_initial_events()
    task = asyncio.create_task(tail_suricata_log_task())
    yield
    task.cancel()


app = FastAPI(title="Network Anomaly Detection System", lifespan=lifespan)

origins = config["web"]["allowed_origins"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class DnsAnomalyConfigUpdate(BaseModel):
    max_queries_per_client_per_minute: int
    max_nxdomain_ratio: float
    high_entropy_threshold: float
    suspicious_tlds: list[str]


class SimulateRequest(BaseModel):
    scenario: str


class AnalyzeRequest(BaseModel):
    alert_id: str | None = None
    prompt: str | None = None


@app.get("/api/config")
def get_config():
    global config, active_config_path
    config, active_config_path = load_config()
    return {
        "config_path": active_config_path,
        "using_system_etc_config": Path(active_config_path) == SYSTEM_CONFIG_PATH,
        "server": config["server"],
        "web": {
            "react_app_url": config["web"]["react_app_url"],
            "api_url": config["web"]["api_url"],
            "allowed_origins": config["web"]["allowed_origins"],
        },
        "monitoring": config["monitoring"],
        "dns_anomaly": config["dns_anomaly"],
        "alerts": {
            "email_to": config["alerts"].get("email_to", []),
            "webhook_configured": bool(config["alerts"].get("webhook_url")),
        },
        "dataset_bucket": config.get("dataset_bucket", {}),
    }


@app.get("/api/dataset")
def get_hf_bucket_dataset(dataset: str | None = None, limit: int = 5):
    from hf_bucket_langchain import fetch_hf_dataset_rows_as_documents

    ds_cfg = config.get("dataset_bucket", {})
    target_ds = dataset or ds_cfg.get("hf_dataset_id", "arks-ai/cicids2017")
    docs = fetch_hf_dataset_rows_as_documents(dataset_name=target_ds, limit=limit)
    return {
        "bucket_uri": ds_cfg.get("bucket_uri", "gs://nads-security-lake/hf-datasets/cicids-dns"),
        "provider": ds_cfg.get("provider", "gcs"),
        "hf_dataset_id": target_ds,
        "document_count": len(docs),
        "documents": [
            {"page_content": d.page_content, "metadata": d.metadata} for d in docs
        ],
    }



@app.put("/api/config/dns_anomaly")
def update_dns_anomaly_config(update: DnsAnomalyConfigUpdate):
    global config
    config["dns_anomaly"] = {
        "max_queries_per_client_per_minute": update.max_queries_per_client_per_minute,
        "max_nxdomain_ratio": update.max_nxdomain_ratio,
        "high_entropy_threshold": update.high_entropy_threshold,
        "suspicious_tlds": update.suspicious_tlds,
    }
    try:
        with open(active_config_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(config, f, sort_keys=False)
    except OSError:
        # Still update in-memory if /etc/nads/config.yaml is read-only
        pass
    return {"status": "updated", "dns_anomaly": config["dns_anomaly"]}


@app.get("/api/status")
def status():
    eve = Path(config["monitoring"]["suricata_eve_path"])
    zeek_dir = Path(config["monitoring"]["zeek_log_dir"])
    zeek_dns = zeek_dir / "dns.log"
    now = time.time()

    # Prune stale 60s windows before reporting client metrics
    active_clients = {}
    for client_ip, dq in list(dns_counts.items()):
        while dq and now - dq[0] > 60:
            dq.popleft()
        if dq:
            active_clients[client_ip] = len(dq)

    return {
        "server_name": config["server"]["name"],
        "environment": config["server"]["environment"],
        "public_ip": config["server"]["public_ip"],
        "interface": config["server"]["listen_interface"],
        "config_path": active_config_path,
        "suricata_log_exists": eve.exists(),
        "zeek_dns_log_exists": zeek_dns.exists(),
        "active_alerts": len(alerts),
        "tracked_dns_clients": len(dns_counts),
        "client_query_rates": active_clients,
        "recent_dns_queries": list(recent_dns_queries)[:25],
    }


@app.get("/api/alerts")
def get_alerts(limit: int = 100):
    return list(alerts)[:limit]


@app.post("/api/events")
def ingest_event(event: dict[str, Any]):
    created = process_suricata_event(event)
    return {"processed": True, "alerts_created": len(created), "alerts": created}


@app.post("/api/simulate")
def simulate_anomaly(req: SimulateRequest):
    scenario = req.scenario.lower()
    created: list[dict[str, Any]] = []

    if scenario == "dns_tunneling":
        created.extend(
            process_suricata_event(
                {
                    "event_type": "dns",
                    "src_ip": "10.0.14.88",
                    "dns": {
                        "rrname": "a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4.k8z9q1w2e3r4.exfil-c2.org",
                        "rrtype": "TXT",
                        "rcode": 0,
                    },
                }
            )
        )
    elif scenario == "dga_nxdomain":
        src = "10.0.14.105"
        for i in range(21):
            created.extend(
                process_suricata_event(
                    {
                        "event_type": "dns",
                        "src_ip": src,
                        "dns": {
                            "rrname": f"q{i}x8k9m2v7p4n{i}.biz",
                            "rrtype": "A",
                            "rcode": 3,
                        },
                    }
                )
            )
    elif scenario == "dns_flood":
        src = "10.0.14.210"
        limit = config["dns_anomaly"]["max_queries_per_client_per_minute"]
        now = time.time()
        dns_counts[src] = deque([now] * limit)
        created.extend(
            process_suricata_event(
                {
                    "event_type": "dns",
                    "src_ip": src,
                    "dns": {
                        "rrname": "api-lookup.internal.example.com",
                        "rrtype": "A",
                        "rcode": 0,
                    },
                }
            )
        )
    elif scenario == "suspicious_tld":
        created.extend(
            process_suricata_event(
                {
                    "event_type": "dns",
                    "src_ip": "10.0.14.54",
                    "dns": {
                        "rrname": "credential-harvest-login.xyz",
                        "rrtype": "A",
                        "rcode": 0,
                    },
                }
            )
        )
    elif scenario == "web_attack":
        created.extend(
            process_suricata_event(
                {
                    "event_type": "alert",
                    "src_ip": "203.0.113.244",
                    "dest_ip": config["server"]["public_ip"],
                    "proto": "TCP",
                    "alert": {
                        "signature": "ET WEB_SERVER Possible CVE-2024 Remote Command Execution Attempt",
                        "category": "Web Application Attack",
                        "severity": 1,
                    },
                }
            )
        )
    else:
        raise HTTPException(status_code=400, detail=f"Unknown scenario: {req.scenario}")

    return {"scenario": scenario, "alerts_triggered": len(created), "latest_alert": created[-1] if created else None}


@app.post("/api/analyze")
def analyze_anomaly(req: AnalyzeRequest):
    target_alert = None
    if req.alert_id:
        for a in alerts:
            if a["id"] == req.alert_id:
                target_alert = a
                break

    context_payload = {
        "server": config["server"],
        "dns_thresholds": config["dns_anomaly"],
        "selected_alert": target_alert,
        "recent_alerts_sample": list(alerts)[:5],
        "operator_question": req.prompt or "Analyze this anomaly and provide Ubuntu/Suricata/Zeek/UFW remediation commands.",
    }

    prompt_text = (
        f"Server & Telemetry Context:\n{json.dumps(context_payload, indent=2)}\n\n"
        f"Operator Request: {context_payload['operator_question']}"
    )

    system_instruction = (
        "You are an Ubuntu Security Operations Center (SOC) AI analyst for a Network Anomaly "
        "Detection System (NADS) running Suricata, Zeek, and a React/FastAPI stack. "
        "Provide concise, actionable root-cause analysis, explain why the DNS or IDS signal triggered "
        "(e.g., Shannon entropy, NXDOMAIN DGA behavior, query flood, or Suricata signature), "
        "and give exact Ubuntu CLI verification/mitigation commands (such as jq on /var/log/suricata/eve.json, "
        "zeek-cut on /opt/zeek/logs/current/dns.log, or ufw/iptables rules)."
    )

    api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    if not api_key:
        raise HTTPException(
            status_code=500,
            detail="Missing GEMINI_API_KEY or GOOGLE_API_KEY in environment (.env).",
        )

    try:
        from google import genai

        client = genai.Client(api_key=api_key)
        interaction = client.interactions.create(
            model="gemini-3.8-flash",
            input=prompt_text,
            system_instruction=system_instruction,
        )
        return {"text": interaction.output_text, "alert_id": req.alert_id}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"AI analysis failed: {exc}") from exc


@app.websocket("/ws/alerts")
async def websocket_alerts(ws: WebSocket):
    await ws.accept()
    last_id = None
    try:
        while True:
            if alerts and alerts[0]["id"] != last_id:
                last_id = alerts[0]["id"]
                await ws.send_json(alerts[0])
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        return
