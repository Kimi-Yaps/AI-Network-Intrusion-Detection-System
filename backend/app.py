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
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
ALERTS_HISTORY_FILE = DATA_DIR / "alerts_history.jsonl"

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
telemetry_history: deque[dict[str, Any]] = deque(maxlen=20)
alert_dedup_cache: dict[tuple[str, str, str], float] = {}
ALERT_COOLDOWN_SECONDS = 60.0

BENIGN_SURICATA_PREFIXES = (
    "SURICATA STREAM",
    "SURICATA Applayer",
    "SURICATA HTTP",
    "SURICATA TCPv4",
    "SURICATA IPv4",
)


def is_benign_suricata_noise(summary: str, evidence: dict[str, Any] | None = None) -> bool:
    """Filters out Suricata's internal TCP/WebSocket stream decode noise on dashboard ports."""
    s = (summary or "").strip()
    if any(s.startswith(prefix) for prefix in BENIGN_SURICATA_PREFIXES):
        return True
    if evidence and isinstance(evidence, dict):
        alert_meta = evidence.get("alert", {})
        if isinstance(alert_meta, dict) and alert_meta.get("category") == "Generic Protocol Command Decode":
            if s.startswith("SURICATA "):
                return True
    return False


def load_persisted_alerts() -> None:
    """Loads previously saved alerts from backend/data/alerts_history.jsonl on startup, pruning stream noise."""
    if not ALERTS_HISTORY_FILE.exists():
        return
    try:
        with open(ALERTS_HISTORY_FILE, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()[-500:]
        kept: list[dict[str, Any]] = []
        seen_keys: set[tuple[str, str, str]] = set()
        for line in lines:
            line = line.strip()
            if not line:
                continue
            item = json.loads(line)
            if is_benign_suricata_noise(item.get("summary", ""), item.get("evidence")):
                continue
            key = (
                str(item.get("source_ip", "")),
                str(item.get("category", "")),
                str(item.get("summary", "")),
            )
            if key in seen_keys:
                continue
            seen_keys.add(key)
            kept.append(item)
            alerts.appendleft(item)
        # Rewrite history file without noisy/duplicate entries
        with open(ALERTS_HISTORY_FILE, "w", encoding="utf-8") as f:
            for item in kept:
                f.write(json.dumps(item) + "\n")
    except Exception:
        pass


def persist_alert(alert: dict[str, Any]) -> None:
    """Appends each alert to backend/data/alerts_history.jsonl so updates never lose data."""
    try:
        with open(ALERTS_HISTORY_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(alert) + "\n")
    except Exception:
        pass


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
) -> dict[str, Any] | None:
    if is_benign_suricata_noise(summary, evidence):
        return None
    now = time.time()
    dedup_subject = category if category in ("DNS volume", "Possible DGA") else summary
    dedup_key = (source_ip, category, dedup_subject)
    last_seen = alert_dedup_cache.get(dedup_key, 0.0)
    if now - last_seen < ALERT_COOLDOWN_SECONDS:
        return None
    alert_dedup_cache[dedup_key] = now

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
    persist_alert(alert)
    return alert


def append_if_created(target: list[dict[str, Any]], alert: dict[str, Any] | None) -> None:
    if alert is not None:
        target.append(alert)


def process_suricata_event(event: dict[str, Any]) -> list[dict[str, Any]]:
    created_alerts: list[dict[str, Any]] = []
    event_type = event.get("event_type")

    if event_type == "alert":
        src = event.get("src_ip", "unknown")
        signature = event.get("alert", {}).get("signature", "Unknown alert")
        severity_num = event.get("alert", {}).get("severity", 3)
        append_if_created(
            created_alerts,
            add_alert(
                severity="high" if severity_num <= 2 else "medium",
                category="IDS signature",
                source_ip=src,
                summary=signature,
                evidence=event,
            ),
        )

    elif event_type == "dns":
        dns_data = event.get("dns", {})
        is_answer = dns_data.get("type") == "answer" or event.get("src_port") == 53
        src = (
            event.get("dest_ip", event.get("src_ip", "unknown"))
            if is_answer
            else event.get("src_ip", "unknown")
        )
        queries_list = dns_data.get("queries")
        first_query = (
            queries_list[0]
            if isinstance(queries_list, list) and len(queries_list) > 0 and isinstance(queries_list[0], dict)
            else {}
        )
        raw_qname = dns_data.get("rrname") or first_query.get("rrname") or ""
        qname = str(raw_qname).rstrip(".")
        rcode = dns_data.get("rcode")
        rrtype = str(dns_data.get("rrtype") or first_query.get("rrtype") or "A")
        now = time.time()

        dq = dns_counts[src]
        if not is_answer:
            dq.append(now)
        while dq and now - dq[0] > 60:
            dq.popleft()

        labels = qname.split(".") if qname else []
        subdomain = ".".join(labels[:-2]) if len(labels) >= 3 else ""
        entropy = round(shannon_entropy(subdomain), 2)
        tld = labels[-1].lower() if len(labels) >= 2 else ""

        if qname or not is_answer:
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
        if not is_answer and len(dq) > max_qpm:
            append_if_created(
                created_alerts,
                add_alert(
                    severity="high",
                    category="DNS volume",
                    source_ip=src,
                    summary=f"High DNS query volume: {len(dq)} queries/minute (threshold: {max_qpm})",
                    evidence={"query": qname, "queries_per_minute": len(dq)},
                ),
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
                append_if_created(
                    created_alerts,
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
                    ),
                )

        if not is_answer and len(labels) >= 3:
            if entropy > config["dns_anomaly"]["high_entropy_threshold"]:
                append_if_created(
                    created_alerts,
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
                    ),
                )

        suspicious_tlds = [
            str(t).lower().lstrip(".")
            for t in config["dns_anomaly"].get("suspicious_tlds", [])
        ]
        if not is_answer and tld and tld in suspicious_tlds:
            append_if_created(
                created_alerts,
                add_alert(
                    severity="medium",
                    category="Suspicious TLD",
                    source_ip=src,
                    summary=f"Query to monitored suspicious TLD (.{tld}): {qname}",
                    evidence={"tld": tld, "query": qname, "rrtype": rrtype},
                ),
            )

    return created_alerts


async def tail_suricata_log_task() -> None:
    """Background task that tails new live events from /var/log/suricata/eve.json on Ubuntu."""
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
    load_persisted_alerts()
    task = asyncio.create_task(tail_suricata_log_task())
    yield
    task.cancel()


app = FastAPI(title="Network Anomaly Detection System", lifespan=lifespan)

# Allow configured origins plus any LAN/VMware IP origin
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


class DnsAnomalyConfigUpdate(BaseModel):
    max_queries_per_client_per_minute: int
    max_nxdomain_ratio: float
    high_entropy_threshold: float
    suspicious_tlds: list[str]


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
        pass
    return {"status": "updated", "dns_anomaly": config["dns_anomaly"]}


@app.get("/api/status")
def status():
    eve = Path(config["monitoring"]["suricata_eve_path"])
    zeek_dir = Path(config["monitoring"]["zeek_log_dir"])
    zeek_dns = zeek_dir / "dns.log"
    now = time.time()

    active_clients = {}
    total_qpm = 0
    for client_ip, dq in list(dns_counts.items()):
        while dq and now - dq[0] > 60:
            dq.popleft()
        if dq:
            active_clients[client_ip] = len(dq)
            total_qpm += len(dq)

    total_nx_5m = 0
    for _ip, nx in list(nxdomain_counts.items()):
        while nx and now - nx[0] > 300:
            nx.popleft()
        total_nx_5m += len(nx)

    max_entropy = round(max((q.get("entropy", 0.0) for q in recent_dns_queries), default=0.0), 2)

    point = {
        "timestamp": time.strftime("%H:%M:%S"),
        "qpm": total_qpm,
        "nxdomain": total_nx_5m,
        "entropy": max_entropy,
        "alerts": len(alerts),
    }
    if not telemetry_history or telemetry_history[-1]["timestamp"] != point["timestamp"]:
        telemetry_history.append(point)

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
        "metrics": {
            "dns_queries_per_min": total_qpm,
            "nxdomain_last_5m": total_nx_5m,
            "max_entropy_bits": max_entropy,
            "history": list(telemetry_history),
        },
    }


@app.get("/api/alerts")
def get_alerts(limit: int = 100):
    return list(alerts)[:limit]


@app.delete("/api/alerts")
def clear_alerts():
    alerts.clear()
    alert_dedup_cache.clear()
    dns_counts.clear()
    nxdomain_counts.clear()
    recent_dns_queries.clear()
    telemetry_history.clear()
    if ALERTS_HISTORY_FILE.exists():
        ALERTS_HISTORY_FILE.unlink(missing_ok=True)
    return {"cleared": True}


@app.post("/api/events")
def ingest_event(event: dict[str, Any]):
    created = process_suricata_event(event)
    return {"processed": True, "alerts_created": len(created), "alerts": created}


def build_deterministic_threat_report(
    target_alert: dict[str, Any] | None,
    operator_question: str,
    hf_docs: list[Any],
) -> str:
    if not target_alert:
        return (
            "=== NADS THREAT & ORIGIN ASSESSMENT ===\n"
            "Status: No active alert selected (0 active threats).\n"
            f"Server: {config['server']['name']} ({config['server']['public_ip']}) on {config['server']['listen_interface']}\n"
            f"Operator Query: {operator_question}\n"
        )

    src_ip = str(target_alert.get("source_ip", "unknown"))
    category = str(target_alert.get("category", "Unknown"))
    severity = str(target_alert.get("severity", "medium")).upper()
    summary = str(target_alert.get("summary", ""))
    ev = target_alert.get("evidence") or {}

    if src_ip.startswith("192.168.150."):
        origin_zone = "VMware NAT / Local Subnet (192.168.150.0/24 — Host/WSL/VM)"
    elif src_ip.startswith(("10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.3", "192.168.")):
        origin_zone = "Private Internal RFC1918 Network"
    elif src_ip.startswith("127."):
        origin_zone = "Loopback / Local Server Process"
    else:
        origin_zone = "External Public Internet Host"

    score_map = {
        "Possible DNS tunneling": (88, "T1071.004 / T1048 — DNS Application Layer C2 & Data Exfiltration"),
        "DNS volume": (82, "T1498 — Network Denial of Service / High-Volume DNS Flood"),
        "IDS signature": (85 if severity == "HIGH" else 68, "T1190 / T1046 — Network Intrusion / Service Exploitation"),
        "Possible DGA": (74, "T1568.002 — Dynamic Resolution: Domain Generation Algorithms"),
        "Suspicious TLD": (62, "T1583.001 — Suspicious / Newly Registered Top-Level Domain"),
    }
    score, mitre = score_map.get(category, (75 if severity == "HIGH" else 55, "T1071 — Network Anomaly"))

    query_target = ev.get("query") or ev.get("dest_ip") or config["server"]["public_ip"]
    iface = ev.get("in_iface") or config["server"]["listen_interface"]
    proto = ev.get("proto") or ("UDP/53 (DNS)" if "DNS" in category or "DGA" in category or "TLD" in category else "TCP/IP")
    hf_snippet = (
        hf_docs[0].page_content[:220]
        if hf_docs and hasattr(hf_docs[0], "page_content")
        else "Correlated against CICIDS / Cybersecurity-Attack-Dataset DNS & network behavioral profiles."
    )

    return (
        f"=== NADS THREAT SCORE & ORIGIN ASSESSMENT ===\n"
        f"• Threat Score      : {score}/100 ({severity} RISK)\n"
        f"• Attack Category   : {category}\n"
        f"• MITRE ATT&CK      : {mitre}\n"
        f"• Trigger Summary   : {summary}\n\n"
        f"=== ORIGIN TRACE (WHERE IT CAME FROM) ===\n"
        f"• Source IP         : {src_ip}\n"
        f"• Network Origin    : {origin_zone}\n"
        f"• Capture Interface : {iface} -> {config['server']['name']} ({config['server']['public_ip']})\n"
        f"• Protocol / Target : {proto} -> {query_target}\n"
        f"• Raw Evidence      : {json.dumps(ev)}\n\n"
        f"=== LANGCHAIN HF BUCKET CORRELATION ===\n"
        f"• Reference Sample  : {hf_snippet}\n\n"
        f"=== UBUNTU / SURICATA / UFW REMEDIATION ===\n"
        f"1. Inspect all Suricata events from {src_ip}:\n"
        f"   sudo jq 'select(.src_ip==\"{src_ip}\")' /var/log/suricata/eve.json | tail -n 20\n"
        f"2. Block {src_ip} at Ubuntu firewall (UFW):\n"
        f"   sudo ufw insert 1 deny from {src_ip} to any\n"
    )


@app.post("/api/analyze")
def analyze_anomaly(req: AnalyzeRequest):
    target_alert = None
    if req.alert_id:
        for a in alerts:
            if a["id"] == req.alert_id:
                target_alert = a
                break
    if target_alert is None and alerts:
        target_alert = alerts[0]

    hf_docs = []
    try:
        from hf_bucket_langchain import fetch_hf_dataset_rows_as_documents

        ds_cfg = config.get("dataset_bucket", {})
        target_ds = ds_cfg.get("hf_dataset_id", "Mandatory/Cybersecurity-Attack-Dataset")
        hf_docs = fetch_hf_dataset_rows_as_documents(dataset_name=target_ds, limit=2)
    except Exception:
        hf_docs = []

    operator_q = req.prompt or "Analyze this anomaly, score the threat, identify its origin, and provide Ubuntu/Suricata/UFW remediation commands."

    api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    if not api_key:
        return {
            "text": build_deterministic_threat_report(target_alert, operator_q, hf_docs),
            "alert_id": req.alert_id,
        }

    context_payload = {
        "server": config["server"],
        "dns_thresholds": config["dns_anomaly"],
        "selected_alert": target_alert,
        "operator_question": operator_q,
    }

    prompt_text = (
        f"Server & Telemetry Context:\n{json.dumps(context_payload, indent=2)}\n\n"
        f"Operator Request: {operator_q}"
    )

    system_instruction = (
        "You are an Ubuntu Security Operations Center (SOC) AI analyst for a Network Anomaly "
        "Detection System (NADS) running Suricata, Zeek, and a React/FastAPI stack. "
        "Provide a 0-100 Threat Score, Origin Trace, root-cause analysis, and exact Ubuntu CLI mitigation commands."
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
    except Exception:
        return {
            "text": build_deterministic_threat_report(target_alert, operator_q, hf_docs),
            "alert_id": req.alert_id,
        }


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
