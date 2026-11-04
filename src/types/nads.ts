export type NavSectionId =
  | 'dashboard'
  | 'alerts'
  | 'configure'
  | 'hf_bucket'
  | 'system';

export interface ServerConfig {
  config_path?: string;
  using_system_etc_config?: boolean;
  server: {
    name: string;
    environment: string;
    listen_interface: string;
    public_ip: string;
    os?: string;
  };
  web?: {
    react_app_url: string;
    api_url: string;
    allowed_origins: string[];
  };
  monitoring: {
    suricata_eve_path: string;
    zeek_log_dir: string;
    poll_interval_seconds: number;
  };
  dns_anomaly: {
    max_queries_per_client_per_minute: number;
    max_nxdomain_ratio: number;
    high_entropy_threshold: number;
    suspicious_tlds: string[];
  };
  alerts: {
    email_to: string[];
    webhook_configured?: boolean;
    webhook_url?: string;
  };
  dataset_bucket?: {
    provider: string;
    bucket_uri: string;
    hf_dataset_id: string;
    split: string;
    streaming: boolean;
  };
}

export interface TelemetryPoint {
  timestamp: string;
  qpm: number;
  nxdomain: number;
  entropy: number;
  alerts: number;
}

export interface ServerStatus {
  server_name: string;
  environment?: string;
  public_ip?: string;
  interface: string;
  config_path?: string;
  suricata_log_exists: boolean;
  zeek_dns_log_exists?: boolean;
  active_alerts: number;
  tracked_dns_clients: number;
  client_query_rates?: Record<string, number>;
  recent_dns_queries?: Array<{
    id: string;
    timestamp: string;
    source_ip: string;
    rrname: string;
    rrtype: string;
    rcode: number;
    entropy: number;
    qpm_for_client: number;
  }>;
  metrics?: {
    dns_queries_per_min: number;
    nxdomain_last_5m: number;
    max_entropy_bits: number;
    history?: TelemetryPoint[];
  };
}

export interface AnomalyAlert {
  id: string;
  timestamp: string;
  severity: 'high' | 'medium' | 'low';
  category: string;
  source_ip: string;
  summary: string;
  evidence: Record<string, unknown>;
}

export interface LangChainDatasetPayload {
  bucket_uri: string;
  endpoint?: string;
  provider: string;
  hf_dataset_id: string;
  source?: 'hf-s3-bucket' | 'hf-datasets-server' | 'fallback';
  error?: string | null;
  document_count: number;
  documents: Array<{
    page_content: string;
    metadata: Record<string, unknown>;
  }>;
}

export interface KpiCardProps {
  label: string;
  value: string;
  trendValue: string;
  trendDirection: 'up' | 'down';
  trendLabel: string;
  color: 'blue' | 'yellow' | 'orange' | 'green';
  iconSymbol: string;
  onActionClick?: () => void;
}

export interface EntityRowItem {
  id: string;
  initials: string;
  badgeColor: string;
  primaryText: string;
  secondaryText: string;
  metricText: string;
  onClick?: () => void;
}

export interface ThreatAssessmentInfo {
  score: number;
  mitre: string;
  originZone: string;
  iface: string;
  proto: string;
  target: string;
  possibleThreat: string;
  remediationCmd: string;
}

export function deriveThreatAndOrigin(
  alert: AnomalyAlert,
  defaultIface = 'ens33',
  serverIp = '192.168.150.129'
): ThreatAssessmentInfo {
  const src = alert.source_ip || 'unknown';
  const ev = alert.evidence || {};

  let originZone = 'External Public Internet';
  if (src.startsWith('192.168.150.')) {
    originZone = 'VMware NAT / Local LAN (192.168.150.0/24)';
  } else if (
    src.startsWith('10.') ||
    src.startsWith('192.168.') ||
    /^172\.(1[6-9]|2\d|3[0-1])\./.test(src)
  ) {
    originZone = 'Private Internal Subnet (RFC1918)';
  } else if (src.startsWith('127.')) {
    originZone = 'Localhost Loopback';
  }

  const iface = String(ev.in_iface || defaultIface);
  const srcPort = ev.src_port ? `:${ev.src_port}` : '';
  const destPort = ev.dest_port ? `:${ev.dest_port}` : '';
  const proto = String(
    ev.proto ||
      (alert.category.includes('DNS') ||
      alert.category.includes('DGA') ||
      alert.category.includes('TLD')
        ? `UDP (${ev.rrtype || 'DNS'})`
        : 'TCP/IP')
  );
  const target = String(ev.query || (ev.dest_ip ? `${ev.dest_ip}${destPort}` : serverIp));

  let score = alert.severity === 'high' ? 85 : alert.severity === 'medium' ? 65 : 40;
  let mitre = 'T1071 — Application Layer Protocol';
  let possibleThreat =
    'Anomalous network activity detected on monitored interface; inspect source host.';

  if (alert.category === 'Possible DNS tunneling') {
    score = 92;
    mitre = 'T1071.004 / T1048 — DNS Tunneling & Data Exfiltration';
    possibleThreat = `High-entropy subdomain payload (${ev.entropy ?? '3.5+'} bits) indicates covert C2 communication or encoded data exfiltration over UDP/53.`;
  } else if (alert.category === 'DNS volume') {
    score = 86;
    mitre = 'T1498 — Network DoS / High-Volume DNS Flood';
    possibleThreat = `Client exceeded safe query rate (${ev.queries_per_minute ?? '120+'}/min), indicating DNS amplification, enumeration, or automated flooding.`;
  } else if (alert.category === 'Possible DGA') {
    score = 78;
    mitre = 'T1568.002 — Domain Generation Algorithm (Malware C2)';
    possibleThreat = `Repeated NXDOMAIN responses (${ev.recent_nxdomain ?? '20+'} in 5m) suggest malware attempting to locate an active command-and-control domain.`;
  } else if (alert.category === 'Suspicious TLD') {
    score = 68;
    mitre = 'T1583.001 — High-Risk / Abused Top-Level Domain';
    possibleThreat = `Lookup to high-risk TLD (.${ev.tld ?? 'xyz/zip/mov/top'}) frequently used for phishing, droppers, and short-lived C2 servers.`;
  } else if (alert.category === 'IDS signature') {
    score = alert.severity === 'high' ? 90 : 74;
    mitre = 'T1046 / T1190 — Network Scan or Exploit Attempt';
    possibleThreat = `Suricata packet inspection matched signature "${alert.summary}" from ${src}${srcPort} targeting ${target}.`;
  }

  const remediationCmd = `sudo ufw insert 1 deny from ${src} to any && sudo jq 'select(.src_ip=="${src}")' /var/log/suricata/eve.json | tail -n 15`;

  return {
    score,
    mitre,
    originZone,
    iface,
    proto,
    target,
    possibleThreat,
    remediationCmd,
  };
}
