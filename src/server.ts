import 'dotenv/config';
import fs from 'node:fs';
import path from 'node:path';
import express from 'express';
import cors from 'cors';
import { GoogleGenAI } from '@google/genai';
import { Document } from '@langchain/core/documents';
import {
  describeBucketError,
  getHfBucketSettings,
  hasHfBucketCredentials,
  listHfBucketObjects,
  loadHfBucketDocuments,
} from './lib/hfBucket.ts';

const hfBucket = getHfBucketSettings();

const app = express();
app.use(cors());
app.use(express.json());

function loadServerConfig() {
  const systemPath = process.env.NADS_CONFIG_PATH || '/etc/nads/config.yaml';
  const localPath = path.resolve(process.cwd(), 'backend', 'config.yaml');
  const activePath = fs.existsSync(systemPath) ? systemPath : localPath;

  return {
    config_path: activePath,
    using_system_etc_config: activePath === systemPath && fs.existsSync(systemPath),
    server: {
      name: 'JB-Web-Server-01',
      environment: 'production',
      listen_interface: 'ens33',
      public_ip: '192.168.150.129',
      os: 'Ubuntu 24.04 LTS',
    },
    web: {
      react_app_url: 'http://192.168.150.129',
      api_url: 'http://192.168.150.129/api',
      allowed_origins: [
        'https://nads.example.com',
        'http://localhost:5173',
        'http://127.0.0.1:5173',
        'http://192.168.150.129',
        'http://192.168.150.129:5173',
      ],
    },
    monitoring: {
      suricata_eve_path: '/var/log/suricata/eve.json',
      zeek_log_dir: '/opt/zeek/logs/current',
      poll_interval_seconds: 2,
    },
    dns_anomaly: {
      max_queries_per_client_per_minute: 120,
      max_nxdomain_ratio: 0.5,
      high_entropy_threshold: 3.5,
      suspicious_tlds: ['zip', 'mov', 'top', 'xyz'],
    },
    alerts: {
      email_to: ['soc@example.com'],
      webhook_configured: false,
    },
    dataset_bucket: {
      provider: 'huggingface-s3',
      endpoint: hfBucket.endpoint,
      bucket_uri: `s3://${hfBucket.bucket}/${hfBucket.key}`,
      hf_dataset_id: 'Mandatory/Cybersecurity-Attack-Dataset',
      split: 'train',
      streaming: true,
    },
  };
}

const config = loadServerConfig();

interface AlertItem {
  id: string;
  timestamp: string;
  severity: 'high' | 'medium' | 'low';
  category: string;
  source_ip: string;
  summary: string;
  evidence: Record<string, unknown>;
}

interface DnsQueryRecord {
  id: string;
  timestamp: string;
  source_ip: string;
  rrname: string;
  rrtype: string;
  rcode: number;
  entropy: number;
  qpm_for_client: number;
}

interface TelemetryPoint {
  timestamp: string;
  qpm: number;
  nxdomain: number;
  entropy: number;
  alerts: number;
}

const alerts: AlertItem[] = [];
const dnsCounts = new Map<string, number[]>();
const nxdomainCounts = new Map<string, number[]>();
const recentDnsQueries: DnsQueryRecord[] = [];
const telemetryHistory: TelemetryPoint[] = [];

function shannonEntropy(value: string): number {
  if (!value) return 0;
  const freq = new Map<string, number>();
  for (const ch of value) {
    freq.set(ch, (freq.get(ch) ?? 0) + 1);
  }
  const total = value.length;
  let sum = 0;
  for (const n of freq.values()) {
    const p = n / total;
    sum -= p * Math.log2(p);
  }
  return sum;
}

function addAlert(
  severity: 'high' | 'medium' | 'low',
  category: string,
  source_ip: string,
  summary: string,
  evidence: Record<string, unknown>
): AlertItem {
  const alert: AlertItem = {
    id: `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
    timestamp: new Date().toISOString(),
    severity,
    category,
    source_ip,
    summary,
    evidence,
  };
  alerts.unshift(alert);
  if (alerts.length > 1000) alerts.pop();
  return alert;
}

function processSuricataEvent(event: Record<string, any>): AlertItem[] {
  const created: AlertItem[] = [];
  const eventType = event.event_type;

  if (eventType === 'alert') {
    const src = event.src_ip || 'unknown';
    const signature = event.alert?.signature || 'Unknown alert';
    const severityNum = event.alert?.severity ?? 3;
    created.push(
      addAlert(
        severityNum <= 2 ? 'high' : 'medium',
        'IDS signature',
        src,
        signature,
        event
      )
    );
  } else if (eventType === 'dns') {
    const dnsData = event.dns || {};
    const src = event.src_ip || 'unknown';
    const qname = String(dnsData.rrname || '').replace(/\.$/, '');
    const rcode = Number(dnsData.rcode ?? 0);
    const rrtype = String(dnsData.rrtype || 'A');
    const now = Date.now() / 1000;

    const dq = dnsCounts.get(src) || [];
    dq.push(now);
    while (dq.length > 0 && now - dq[0] > 60) dq.shift();
    dnsCounts.set(src, dq);

    const labels = qname ? qname.split('.') : [];
    const subdomain = labels.length >= 3 ? labels.slice(0, -2).join('.') : '';
    const entropy = Number(shannonEntropy(subdomain).toFixed(2));
    const tld = labels.length >= 2 ? labels[labels.length - 1].toLowerCase() : '';

    recentDnsQueries.unshift({
      id: `dns-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
      timestamp: new Date().toISOString(),
      source_ip: src,
      rrname: qname,
      rrtype,
      rcode,
      entropy,
      qpm_for_client: dq.length,
    });
    if (recentDnsQueries.length > 250) recentDnsQueries.pop();

    const maxQpm = config.dns_anomaly.max_queries_per_client_per_minute;
    if (dq.length > maxQpm) {
      created.push(
        addAlert(
          'high',
          'DNS volume',
          src,
          `High DNS query volume: ${dq.length} queries/minute (threshold: ${maxQpm})`,
          { query: qname, queries_per_minute: dq.length }
        )
      );
    }

    if (rcode === 3) {
      const nx = nxdomainCounts.get(src) || [];
      nx.push(now);
      while (nx.length > 0 && now - nx[0] > 300) nx.shift();
      nxdomainCounts.set(src, nx);

      const nxRatio = nx.length / Math.max(dq.length, 1);
      if (nx.length >= 20 || (dq.length >= 10 && nxRatio >= config.dns_anomaly.max_nxdomain_ratio)) {
        created.push(
          addAlert(
            'medium',
            'Possible DGA',
            src,
            `Repeated NXDOMAIN responses from ${src} (${nx.length} in 5m)`,
            { recent_nxdomain: nx.length, nxdomain_ratio: Number(nxRatio.toFixed(2)), query: qname }
          )
        );
      }
    }

    if (labels.length >= 3 && entropy > config.dns_anomaly.high_entropy_threshold) {
      created.push(
        addAlert(
          'high',
          'Possible DNS tunneling',
          src,
          `High-entropy DNS label (${entropy} bits): ${qname}`,
          { entropy, subdomain, query: qname, rrtype }
        )
      );
    }

    if (tld && config.dns_anomaly.suspicious_tlds.includes(tld)) {
      created.push(
        addAlert(
          'medium',
          'Suspicious TLD',
          src,
          `Query to monitored suspicious TLD (.${tld}): ${qname}`,
          { tld, query: qname, rrtype }
        )
      );
    }
  }
  return created;
}

// Tail /var/log/suricata/eve.json continuously when running on Ubuntu
let lastEveSize = -1;
function pollSuricataEveLog() {
  const evePath = config.monitoring.suricata_eve_path;
  if (!fs.existsSync(evePath)) return;
  try {
    const stat = fs.statSync(evePath);
    if (lastEveSize === -1 || stat.size < lastEveSize) {
      lastEveSize = stat.size;
      return;
    }
    if (stat.size === lastEveSize) return;

    const startOffset = lastEveSize;
    const lengthToRead = stat.size - startOffset;
    if (lengthToRead <= 0) return;

    const fd = fs.openSync(evePath, 'r');
    const buffer = Buffer.alloc(lengthToRead);
    fs.readSync(fd, buffer, 0, lengthToRead, startOffset);
    fs.closeSync(fd);
    lastEveSize = stat.size;

    const lines = buffer.toString('utf8').split(/\r?\n/);
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed.startsWith('{')) continue;
      try {
        processSuricataEvent(JSON.parse(trimmed));
      } catch {
        // ignore partial JSON line
      }
    }
  } catch {
    // ignore read error
  }
}
setInterval(pollSuricataEveLog, 1500);
pollSuricataEveLog();

let lastBucketError: string | null = null;
let lastBucketSource: 'hf-s3-bucket' | 'hf-datasets-server' | 'fallback' = 'fallback';

async function loadHfBucketLangChainDocs(
  datasetId: string,
  limit = 5,
  key?: string
): Promise<Document[]> {
  if (hasHfBucketCredentials()) {
    try {
      const result = await loadHfBucketDocuments(limit, key);
      if (result.documents.length > 0) {
        lastBucketError = null;
        lastBucketSource = 'hf-s3-bucket';
        return result.documents;
      }
      lastBucketError = `Object ${result.key} is empty`;
    } catch (err) {
      lastBucketError = err instanceof Error ? err.message : String(err);
      console.warn(`[nads] HF bucket read failed: ${lastBucketError}`);
    }
  } else {
    lastBucketError =
      'No bucket credentials (AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY or HUGGINGFACE_API_KEY)';
  }

  try {
    const params = new URLSearchParams({
      dataset: datasetId,
      config: 'default',
      split: 'train',
      offset: '0',
      length: String(limit),
    });
    const res = await fetch(`https://datasets-server.huggingface.co/rows?${params.toString()}`);
    if (res.ok) {
      const data = (await res.json()) as {
        rows?: Array<{ row: Record<string, unknown>; row_idx: number }>;
      };
      if (data.rows && data.rows.length > 0) {
        lastBucketSource = 'hf-datasets-server';
        return data.rows.map(
          (item) =>
            new Document({
              pageContent: JSON.stringify(item.row),
              metadata: {
                dataset: datasetId,
                bucket_uri: config.dataset_bucket.bucket_uri,
                row_idx: item.row_idx,
              },
            })
        );
      }
    }
  } catch {
    // ignore
  }

  lastBucketSource = 'fallback';
  return [];
}

app.get('/api/config', (_req, res) => {
  res.json(config);
});

app.put('/api/config/dns_anomaly', (req, res) => {
  const {
    max_queries_per_client_per_minute,
    max_nxdomain_ratio,
    high_entropy_threshold,
    suspicious_tlds,
  } = req.body;
  config.dns_anomaly = {
    max_queries_per_client_per_minute: Number(max_queries_per_client_per_minute),
    max_nxdomain_ratio: Number(max_nxdomain_ratio),
    high_entropy_threshold: Number(high_entropy_threshold),
    suspicious_tlds: Array.isArray(suspicious_tlds)
      ? suspicious_tlds
      : config.dns_anomaly.suspicious_tlds,
  };
  res.json({ status: 'updated', dns_anomaly: config.dns_anomaly });
});

app.get('/api/status', (_req, res) => {
  const now = Date.now() / 1000;
  const activeClients: Record<string, number> = {};
  let totalQpm = 0;

  for (const [ip, dq] of dnsCounts.entries()) {
    while (dq.length > 0 && now - dq[0] > 60) dq.shift();
    if (dq.length > 0) {
      activeClients[ip] = dq.length;
      totalQpm += dq.length;
    }
  }

  let totalNx5m = 0;
  for (const [, nx] of nxdomainCounts.entries()) {
    while (nx.length > 0 && now - nx[0] > 300) nx.shift();
    totalNx5m += nx.length;
  }

  const maxEntropy = Number(
    recentDnsQueries.reduce((max, q) => (q.entropy > max ? q.entropy : max), 0).toFixed(2)
  );

  const timeLabel = new Date().toLocaleTimeString('en-US', { hour12: false });
  if (
    telemetryHistory.length === 0 ||
    telemetryHistory[telemetryHistory.length - 1].timestamp !== timeLabel
  ) {
    telemetryHistory.push({
      timestamp: timeLabel,
      qpm: totalQpm,
      nxdomain: totalNx5m,
      entropy: maxEntropy,
      alerts: alerts.length,
    });
    if (telemetryHistory.length > 20) telemetryHistory.shift();
  }

  res.json({
    server_name: config.server.name,
    environment: config.server.environment,
    public_ip: config.server.public_ip,
    interface: config.server.listen_interface,
    config_path: config.config_path,
    suricata_log_exists: fs.existsSync(config.monitoring.suricata_eve_path),
    zeek_dns_log_exists: fs.existsSync(path.join(config.monitoring.zeek_log_dir, 'dns.log')),
    active_alerts: alerts.length,
    tracked_dns_clients: dnsCounts.size,
    client_query_rates: activeClients,
    recent_dns_queries: recentDnsQueries.slice(0, 25),
    metrics: {
      dns_queries_per_min: totalQpm,
      nxdomain_last_5m: totalNx5m,
      max_entropy_bits: maxEntropy,
      history: telemetryHistory,
    },
  });
});

app.get('/api/alerts', (req, res) => {
  const limit = Number(req.query.limit || 100);
  res.json(alerts.slice(0, limit));
});

app.delete('/api/alerts', (_req, res) => {
  alerts.length = 0;
  recentDnsQueries.length = 0;
  telemetryHistory.length = 0;
  dnsCounts.clear();
  nxdomainCounts.clear();
  res.json({ cleared: true });
});

app.post('/api/events', (req, res) => {
  const created = processSuricataEvent(req.body || {});
  res.json({ processed: true, alerts_created: created.length, alerts: created });
});

app.get('/api/dataset', async (req, res) => {
  const targetDs = String(req.query.dataset || config.dataset_bucket.hf_dataset_id);
  const key = req.query.key ? String(req.query.key) : undefined;
  const limit = Math.min(Number(req.query.limit || 5), 100);
  const docs = await loadHfBucketLangChainDocs(targetDs, limit, key);
  res.json({
    bucket_uri: `s3://${hfBucket.bucket}/${key || hfBucket.key}`,
    endpoint: hfBucket.endpoint,
    provider: config.dataset_bucket.provider,
    hf_dataset_id: targetDs,
    source: lastBucketSource,
    error: lastBucketSource === 'hf-s3-bucket' ? null : lastBucketError,
    document_count: docs.length,
    documents: docs.map((d) => ({ page_content: d.pageContent, metadata: d.metadata })),
  });
});

app.get('/api/dataset/objects', async (_req, res) => {
  try {
    const keys = await listHfBucketObjects(100);
    res.json({ endpoint: hfBucket.endpoint, bucket: hfBucket.bucket, keys });
  } catch (err) {
    res.status(502).json({
      error: describeBucketError(err, hfBucket.bucket),
    });
  }
});

app.post('/api/analyze', async (req, res) => {
  try {
    const { alert_id, prompt } = req.body;
    const targetAlert = alert_id ? alerts.find((a) => a.id === alert_id) : alerts[0];
    const hfDocs = await loadHfBucketLangChainDocs(config.dataset_bucket.hf_dataset_id, 3);

    const contextPayload = {
      server: config.server,
      dns_thresholds: config.dns_anomaly,
      selected_alert: targetAlert,
      langchain_hf_bucket_docs: hfDocs.map((d) => ({
        pageContent: d.pageContent,
        metadata: d.metadata,
      })),
      operator_question:
        prompt ||
        'Analyze this anomaly using the Hugging Face bucket threat dataset context and provide Ubuntu/Suricata/Zeek/UFW remediation commands.',
    };

    const apiKey = process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY;
    const client = new GoogleGenAI({ apiKey });

    const interaction = await client.interactions.create({
      model: 'gemini-3.8-flash',
      input: `Server & Telemetry Context:\n${JSON.stringify(contextPayload, null, 2)}\n\nOperator Request: ${contextPayload.operator_question}`,
      system_instruction:
        'You are an Ubuntu Security Operations Center (SOC) AI analyst for a Network Anomaly Detection System (NADS) running Suricata, Zeek, LangChain, and a React/FastAPI stack. Provide concise root-cause analysis, correlate with the LangChain Hugging Face bucket dataset context, and give exact Ubuntu CLI verification/mitigation commands.',
    });

    res.json({ text: interaction.output_text, alert_id });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to analyze anomaly with Gemini' });
  }
});

app.post('/api/generate', async (req, res) => {
  try {
    const { prompt } = req.body;
    const apiKey = process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY;
    const client = new GoogleGenAI({ apiKey });
    const interaction = await client.interactions.create({
      model: 'gemini-3.8-flash',
      input: String(prompt || ''),
    });

    res.json({ text: interaction.output_text });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to generate content' });
  }
});

const port = process.env.PORT || 8000;
app.listen(port, () => {
  console.log(`NADS Backend server running on http://0.0.0.0:${port}`);
});
