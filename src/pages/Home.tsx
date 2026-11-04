import { useCallback, useEffect, useMemo, useState } from 'react';
import AlertsTable from '../components/AlertsTable';
import EntityListCard from '../components/EntityListCard';
import KpiCard from '../components/KpiCard';
import Navbar from '../components/Navbar';
import OverviewChart from '../components/OverviewChart';
import TopHeader from '../components/TopHeader';
import type {
  AnomalyAlert,
  EntityRowItem,
  KpiCardProps,
  LangChainDatasetPayload,
  NavSectionId,
  ServerConfig,
  ServerStatus,
} from '../types/nads';

function getApiCandidates(): string[] {
  const list: string[] = [];
  if (import.meta.env.VITE_API_URL) {
    list.push(String(import.meta.env.VITE_API_URL).replace(/\/$/, ''));
  }
  if (typeof window !== 'undefined') {
    const host = window.location.hostname;
    if (host && host !== 'localhost' && host !== '127.0.0.1') {
      list.push(`http://${host}:8000`);
      list.push(window.location.origin);
    }
  }
  list.push('http://192.168.150.129:8000');
  list.push('http://localhost:8000');
  return Array.from(new Set(list));
}

const INITIAL_CONFIG: ServerConfig = {
  config_path: '/etc/nads/config.yaml',
  using_system_etc_config: false,
  server: {
    name: 'Connecting...',
    environment: 'production',
    listen_interface: 'ens33',
    public_ip: '192.168.150.129',
    os: 'Ubuntu 24.04 LTS',
  },
  web: {
    react_app_url: 'http://192.168.150.129',
    api_url: 'http://192.168.150.129:8000/api',
    allowed_origins: ['http://192.168.150.129', 'http://localhost:5173'],
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
    bucket_uri: 's3://MyBucket/example.txt',
    hf_dataset_id: 'Mandatory/Cybersecurity-Attack-Dataset',
    split: 'train',
    streaming: true,
  },
};

const SECTION_TITLES: Record<NavSectionId, string> = {
  dashboard: 'Dashboard',
  alerts: 'Live Alerts & Anomalies',
  dns: 'DNS Behavioral Telemetry',
  monitoring: 'Suricata & Zeek Sensors',
  rules: 'Risk & Anomaly Rules',
  ai_analyst: 'AI SOC Threat Analyst',
  hf_bucket: 'Hugging Face Bucket & LangChain RAG',
  configure: 'Server Configuration (/etc/nads/config.yaml)',
  system: 'Ubuntu System Status',
};

function Home() {
  const [activeApi, setActiveApi] = useState<string>('http://192.168.150.129:8000');
  const [connected, setConnected] = useState<boolean>(false);
  const [activeSection, setActiveSection] = useState<NavSectionId>('dashboard');
  const [searchQuery, setSearchQuery] = useState<string>('');

  const [config, setConfig] = useState<ServerConfig>(INITIAL_CONFIG);
  const [status, setStatus] = useState<ServerStatus>({
    server_name: INITIAL_CONFIG.server.name,
    environment: INITIAL_CONFIG.server.environment,
    public_ip: INITIAL_CONFIG.server.public_ip,
    interface: INITIAL_CONFIG.server.listen_interface,
    config_path: INITIAL_CONFIG.config_path,
    suricata_log_exists: false,
    zeek_dns_log_exists: false,
    active_alerts: 0,
    tracked_dns_clients: 0,
    client_query_rates: {},
    recent_dns_queries: [],
    metrics: {
      dns_queries_per_min: 0,
      nxdomain_last_5m: 0,
      max_entropy_bits: 0,
      history: [],
    },
  });
  const [alerts, setAlerts] = useState<AnomalyAlert[]>([]);
  const [datasetInfo, setDatasetInfo] = useState<LangChainDatasetPayload>({
    bucket_uri: 's3://MyBucket/example.txt',
    provider: 'huggingface-s3',
    hf_dataset_id: 'Mandatory/Cybersecurity-Attack-Dataset',
    document_count: 0,
    documents: [],
  });

  // Editable DNS threshold state
  const [maxQpm, setMaxQpm] = useState<number>(120);
  const [maxNxRatio, setMaxNxRatio] = useState<number>(0.5);
  const [entropyThreshold, setEntropyThreshold] = useState<number>(3.5);
  const [tldsInput, setTldsInput] = useState<string>('zip, mov, top, xyz');
  const [configSaveMsg, setConfigSaveMsg] = useState<string>('');
  const [configLoadedOnce, setConfigLoadedOnce] = useState<boolean>(false);

  // AI Analyst state
  const [selectedAlert, setSelectedAlert] = useState<AnomalyAlert | null>(null);
  const [customPrompt, setCustomPrompt] = useState<string>('');
  const [aiAnalysis, setAiAnalysis] = useState<string>('');
  const [analyzing, setAnalyzing] = useState<boolean>(false);

  const loadTelemetry = useCallback(async () => {
    const candidates = getApiCandidates();
    for (const base of candidates) {
      try {
        const [cRes, sRes, aRes, dRes] = await Promise.all([
          fetch(`${base}/api/config`),
          fetch(`${base}/api/status`),
          fetch(`${base}/api/alerts?limit=100`),
          fetch(`${base}/api/dataset`),
        ]);
        if (cRes.ok && sRes.ok && aRes.ok) {
          const [cData, sData, aData] = await Promise.all([
            cRes.json(),
            sRes.json(),
            aRes.json(),
          ]);
          setConfig(cData);
          setStatus(sData);
          setAlerts(aData);
          if (dRes.ok) {
            setDatasetInfo(await dRes.json());
          }
          if (!configLoadedOnce) {
            setMaxQpm(cData.dns_anomaly.max_queries_per_client_per_minute);
            setMaxNxRatio(cData.dns_anomaly.max_nxdomain_ratio);
            setEntropyThreshold(cData.dns_anomaly.high_entropy_threshold);
            setTldsInput((cData.dns_anomaly.suspicious_tlds || []).join(', '));
            setConfigLoadedOnce(true);
          }
          setActiveApi(base);
          setConnected(true);
          return;
        }
      } catch {
        // try next candidate
      }
    }
    setConnected(false);
  }, [configLoadedOnce]);

  useEffect(() => {
    const initial = setTimeout(() => {
      void loadTelemetry();
    }, 0);
    const timer = setInterval(() => {
      void loadTelemetry();
    }, 2000);
    return () => {
      clearTimeout(initial);
      clearInterval(timer);
    };
  }, [loadTelemetry]);

  useEffect(() => {
    if (!connected) return;
    const wsUrl = `${activeApi.replace(/^http/, 'ws')}/ws/alerts`;
    let ws: WebSocket | null = null;
    try {
      ws = new WebSocket(wsUrl);
      ws.onmessage = (ev) => {
        try {
          const incoming = JSON.parse(ev.data) as AnomalyAlert;
          setAlerts((prev) =>
            prev.some((a) => a.id === incoming.id) ? prev : [incoming, ...prev]
          );
        } catch {
          // ignore malformed ws frame
        }
      };
    } catch {
      // polling already active every 2s
    }
    return () => {
      ws?.close();
    };
  }, [activeApi, connected]);

  const triggerSimulation = async (scenario: string) => {
    try {
      await fetch(`${activeApi}/api/simulate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario }),
      });
      await loadTelemetry();
    } catch {
      // ignore if backend unreachable
    }
  };

  const handleSaveDnsConfig = async () => {
    const updatedTlds = tldsInput
      .split(',')
      .map((s) => s.trim().replace(/^\./, ''))
      .filter(Boolean);

    const payload = {
      max_queries_per_client_per_minute: Number(maxQpm),
      max_nxdomain_ratio: Number(maxNxRatio),
      high_entropy_threshold: Number(entropyThreshold),
      suspicious_tlds: updatedTlds,
    };

    try {
      const res = await fetch(`${activeApi}/api/config/dns_anomaly`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      if (res.ok) {
        setConfigSaveMsg('Saved to backend server configuration.');
        await loadTelemetry();
        return;
      }
    } catch {
      setConfigSaveMsg('Failed to reach backend API.');
    }
  };

  const analyzeWithAi = async (alertToInspect?: AnomalyAlert) => {
    const target = alertToInspect || selectedAlert || alerts[0];
    if (alertToInspect) {
      setSelectedAlert(alertToInspect);
      setActiveSection('ai_analyst');
    }
    setAnalyzing(true);
    setAiAnalysis('');

    try {
      const res = await fetch(`${activeApi}/api/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          alert_id: target?.id,
          prompt:
            customPrompt.trim() ||
            `Analyze this ${target?.category || 'network'} alert from ${target?.source_ip || 'host'} (${target?.summary || 'live telemetry'}) correlated with our Hugging Face bucket dataset and provide Ubuntu/Suricata/Zeek mitigation steps.`,
        }),
      });
      const data = await res.json();
      setAiAnalysis(data.text || data.detail || data.error || 'No analysis returned.');
    } catch {
      setAiAnalysis('Backend API unreachable. Ensure nads-api or npm run server is running on port 8000.');
    } finally {
      setAnalyzing(false);
    }
  };

  const filteredAlerts = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    if (!q) return alerts;
    return alerts.filter(
      (a) =>
        a.source_ip.toLowerCase().includes(q) ||
        a.category.toLowerCase().includes(q) ||
        a.summary.toLowerCase().includes(q)
    );
  }, [alerts, searchQuery]);

  const liveQpm = status.metrics?.dns_queries_per_min ?? 0;
  const liveNx = status.metrics?.nxdomain_last_5m ?? 0;
  const liveEntropy = status.metrics?.max_entropy_bits ?? 0;
  const liveHistory = status.metrics?.history ?? [];

  const kpiCards: KpiCardProps[] = [
    {
      label: 'DNS Queries (1m)',
      value: `${liveQpm}/m`,
      trendValue: `${status.tracked_dns_clients} clients`,
      trendDirection: 'up',
      trendLabel: `limit ${config.dns_anomaly.max_queries_per_client_per_minute}/m`,
      color: 'blue',
      iconSymbol: '◷',
      onActionClick: () => setActiveSection('dns'),
    },
    {
      label: 'NXDOMAIN (5m)',
      value: `${liveNx}`,
      trendValue: liveNx >= 20 ? 'DGA Risk' : 'Normal',
      trendDirection: liveNx >= 20 ? 'up' : 'down',
      trendLabel: `max ratio ${config.dns_anomaly.max_nxdomain_ratio}`,
      color: 'yellow',
      iconSymbol: '⚑',
      onActionClick: () => void triggerSimulation('dga_nxdomain'),
    },
    {
      label: 'Peak Entropy',
      value: `${liveEntropy} bits`,
      trendValue:
        liveEntropy > config.dns_anomaly.high_entropy_threshold ? 'High Entropy' : 'Normal',
      trendDirection: 'up',
      trendLabel: `threshold ${config.dns_anomaly.high_entropy_threshold}b`,
      color: 'orange',
      iconSymbol: '⚡',
      onActionClick: () => void triggerSimulation('dns_tunneling'),
    },
    {
      label: 'Active Alerts',
      value: `${alerts.length}`,
      trendValue: `${alerts.filter((a) => a.severity === 'high').length} high`,
      trendDirection: 'up',
      trendLabel: `on ${status.interface}`,
      color: 'green',
      iconSymbol: '🛡',
      onActionClick: () => setActiveSection('alerts'),
    },
  ];

  const palette = ['#ff6b00', '#2563eb', '#10b981', '#8b5cf6'];
  const topSourceIpItems: EntityRowItem[] = filteredAlerts.slice(0, 4).map((alert, idx) => ({
    id: `src-${alert.id}`,
    initials: alert.source_ip.split('.').slice(-1)[0] || 'IP',
    badgeColor: palette[idx % palette.length],
    primaryText: alert.source_ip,
    secondaryText: alert.category,
    metricText: alert.severity.toUpperCase(),
    onClick: () => void analyzeWithAi(alert),
  }));

  const topSensorDepartments: EntityRowItem[] = [
    {
      id: 'dep-suricata',
      initials: 'SR',
      badgeColor: '#ff6b00',
      primaryText: 'Suricata EVE Sensor',
      secondaryText: config.monitoring.suricata_eve_path,
      metricText: status.suricata_log_exists ? 'LIVE' : 'WAITING',
      onClick: () => setActiveSection('monitoring'),
    },
    {
      id: 'dep-zeek',
      initials: 'ZK',
      badgeColor: '#2563eb',
      primaryText: 'Zeek DNS Analyzer',
      secondaryText: `${config.monitoring.zeek_log_dir}/dns.log`,
      metricText: `${status.tracked_dns_clients} hosts`,
      onClick: () => setActiveSection('dns'),
    },
    {
      id: 'dep-hf',
      initials: 'HF',
      badgeColor: '#10b981',
      primaryText: 'HF Dataset Bucket (LangChain)',
      secondaryText: datasetInfo.bucket_uri,
      metricText: `${datasetInfo.document_count} docs`,
      onClick: () => setActiveSection('hf_bucket'),
    },
    {
      id: 'dep-cfg',
      initials: 'CF',
      badgeColor: '#f59e0b',
      primaryText: 'Ubuntu Server Config',
      secondaryText: config.config_path || '/etc/nads/config.yaml',
      metricText: config.server.listen_interface,
      onClick: () => setActiveSection('configure'),
    },
  ];

  return (
    <div className="tm-app-frame">
      <div className="tm-window">
        <Navbar
          activeSection={activeSection}
          onSelectSection={setActiveSection}
          searchQuery={searchQuery}
          onSearchChange={setSearchQuery}
          alertCount={alerts.length}
          serverName={status.server_name}
          connected={connected}
        />

        <main className="tm-main">
          <TopHeader
            title={SECTION_TITLES[activeSection]}
            serverName={status.server_name}
            interfaceName={status.interface}
            connected={connected}
            onRefresh={() => void loadTelemetry()}
            onOpenSettings={() => setActiveSection('configure')}
          />

          <section className="tm-kpi-row" aria-label="Key Security Metrics">
            {kpiCards.map((card) => (
              <KpiCard key={card.label} {...card} />
            ))}
          </section>

          {activeSection === 'dashboard' && (
            <>
              <OverviewChart
                history={liveHistory}
                totalDnsQueries={`${liveQpm}/m`}
                nxdomainCount={`${liveNx}`}
                entropyRate={`${liveEntropy}b`}
                alertScore={`${alerts.length}`}
              />

              <div className="tm-bottom-grid">
                <EntityListCard
                  title="Top Source IPs"
                  filterLabel="Live alert sources"
                  items={topSourceIpItems}
                  actionLabel="Triage"
                />

                <EntityListCard
                  title="Active Sensors & Config"
                  filterLabel="By subsystem"
                  items={topSensorDepartments}
                  actionLabel="Inspect"
                />
              </div>

              <AlertsTable
                title="Live Network & DNS Anomalies"
                caption={`Live telemetry ingested from ${status.server_name} (${config.server.public_ip})`}
                alerts={filteredAlerts}
                analyzing={analyzing}
                onAnalyzeAlert={(a) => void analyzeWithAi(a)}
                onSimulate={(scenario) => void triggerSimulation(scenario)}
                maxQpm={config.dns_anomaly.max_queries_per_client_per_minute}
              />
            </>
          )}

          {(activeSection === 'alerts' || activeSection === 'dns') && (
            <AlertsTable
              title={
                activeSection === 'dns'
                  ? 'DNS Behavioral Anomalies (Entropy, DGA, Floods, TLDs)'
                  : 'All Suricata & Zeek Anomaly Alerts'
              }
              caption="Filtered live stream from /var/log/suricata/eve.json and /opt/zeek/logs/current/dns.log"
              alerts={
                activeSection === 'dns'
                  ? filteredAlerts.filter((a) => a.category !== 'IDS signature')
                  : filteredAlerts
              }
              analyzing={analyzing}
              onAnalyzeAlert={(a) => void analyzeWithAi(a)}
              onSimulate={(scenario) => void triggerSimulation(scenario)}
              maxQpm={config.dns_anomaly.max_queries_per_client_per_minute}
            />
          )}

          {activeSection === 'monitoring' && (
            <section className="dashboard-section">
              <div className="tm-card-header">
                <h2 className="tm-card-title">
                  Live DNS Query Telemetry ({config.monitoring.suricata_eve_path})
                </h2>
                <span className="tm-pill-select">
                  {(status.recent_dns_queries ?? []).length} recent queries
                </span>
              </div>
              <div className="table-wrapper" tabIndex={0} role="region" aria-label="Live DNS Queries">
                <table>
                  <thead>
                    <tr>
                      <th scope="col">Time</th>
                      <th scope="col">Client IP</th>
                      <th scope="col">Queried Domain (rrname)</th>
                      <th scope="col">Type</th>
                      <th scope="col">RCode</th>
                      <th scope="col">Entropy (bits)</th>
                      <th scope="col">Client QPM</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(status.recent_dns_queries ?? []).length === 0 ? (
                      <tr>
                        <td colSpan={7} style={{ textAlign: 'center', color: 'var(--text-muted)' }}>
                          No live DNS queries captured yet. Run dig @{config.server.public_ip}{' '}
                          example.com to test.
                        </td>
                      </tr>
                    ) : (
                      (status.recent_dns_queries ?? []).map((q) => (
                        <tr key={q.id}>
                          <td>{new Date(q.timestamp).toLocaleTimeString()}</td>
                          <td>
                            <code>{q.source_ip}</code>
                          </td>
                          <td>
                            <code>{q.rrname || '(root)'}</code>
                          </td>
                          <td>{q.rrtype}</td>
                          <td>{String(q.rcode ?? 'NOERROR')}</td>
                          <td>{q.entropy}</td>
                          <td>{q.qpm_for_client}</td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </section>
          )}

          {activeSection === 'configure' && (
            <div className="tm-bottom-grid">
              <section className="dashboard-section" style={{ marginBottom: 0 }}>
                <div className="tm-card-header">
                  <h2 className="tm-card-title">Tune DNS Anomaly Thresholds</h2>
                </div>
                <div className="config-form-grid">
                  <label>
                    Max Queries / Client / Minute
                    <input
                      type="number"
                      value={maxQpm}
                      onChange={(e) => setMaxQpm(Number(e.target.value))}
                    />
                  </label>
                  <label>
                    Max NXDOMAIN Ratio (0.0 - 1.0)
                    <input
                      type="number"
                      step="0.05"
                      value={maxNxRatio}
                      onChange={(e) => setMaxNxRatio(Number(e.target.value))}
                    />
                  </label>
                  <label>
                    Shannon Entropy Threshold (bits)
                    <input
                      type="number"
                      step="0.1"
                      value={entropyThreshold}
                      onChange={(e) => setEntropyThreshold(Number(e.target.value))}
                    />
                  </label>
                  <label>
                    Suspicious TLDs (comma-separated)
                    <input
                      type="text"
                      value={tldsInput}
                      onChange={(e) => setTldsInput(e.target.value)}
                    />
                  </label>
                </div>
                <div
                  style={{
                    marginTop: '1rem',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.75rem',
                    flexWrap: 'wrap',
                  }}
                >
                  <button
                    type="button"
                    className="action-btn primary"
                    onClick={() => void handleSaveDnsConfig()}
                  >
                    Save to Server Config
                  </button>
                  <button
                    type="button"
                    className="action-btn"
                    onClick={async () => {
                      await fetch(`${activeApi}/api/alerts`, { method: 'DELETE' });
                      setConfigSaveMsg('Cleared alert history.');
                      await loadTelemetry();
                    }}
                  >
                    Clear Alert History
                  </button>
                  {configSaveMsg && (
                    <span style={{ fontSize: '0.82rem', color: '#10b981', fontWeight: 600 }}>
                      {configSaveMsg}
                    </span>
                  )}
                </div>
              </section>

              <section className="dashboard-section" style={{ marginBottom: 0 }}>
                <div className="tm-card-header">
                  <h2 className="tm-card-title">
                    Server Configuration ({config.config_path || '/etc/nads/config.yaml'})
                  </h2>
                </div>
                <pre className="code-panel">{JSON.stringify(config, null, 2)}</pre>
              </section>
            </div>
          )}

          {activeSection === 'system' && (
            <div className="tm-bottom-grid">
              <section className="dashboard-section" style={{ marginBottom: 0 }}>
                <div className="tm-card-header">
                  <h2 className="tm-card-title">Ubuntu Host &amp; Sensor Health</h2>
                  <span className="tm-pill-select">
                    {connected ? 'Backend Online' : 'Backend Offline'}
                  </span>
                </div>
                <div className="config-form-grid">
                  <div>
                    <strong>Server Name:</strong> {status.server_name}
                  </div>
                  <div>
                    <strong>OS:</strong> {config.server.os}
                  </div>
                  <div>
                    <strong>Bind IP:</strong> <code>{status.public_ip}</code>
                  </div>
                  <div>
                    <strong>Capture Interface:</strong> <code>{status.interface}</code>
                  </div>
                  <div>
                    <strong>Suricata EVE Log:</strong>{' '}
                    {status.suricata_log_exists ? 'Active (/var/log/suricata/eve.json)' : 'Missing'}
                  </div>
                  <div>
                    <strong>Active API Endpoint:</strong> <code>{activeApi}</code>
                  </div>
                </div>
              </section>

              <section className="dashboard-section" style={{ marginBottom: 0 }}>
                <div className="tm-card-header">
                  <h2 className="tm-card-title">Live /api/status Payload</h2>
                </div>
                <pre className="code-panel">{JSON.stringify(status, null, 2)}</pre>
              </section>
            </div>
          )}

          {activeSection === 'rules' && (
            <section className="dashboard-section">
              <div className="tm-card-header">
                <h2 className="tm-card-title">
                  DNS &amp; Web Anomaly Detection Matrix (Suricata EVE + Zeek dns.log)
                </h2>
              </div>
              <div
                tabIndex={0}
                role="region"
                aria-labelledby="dns-rules-caption"
                className="table-wrapper"
              >
                <table>
                  <caption id="dns-rules-caption">
                    Active behavioral &amp; signature rules on {status.server_name} (
                    {status.interface})
                  </caption>
                  <thead>
                    <tr>
                      <th scope="col">Anomaly Type</th>
                      <th scope="col">Detection Signal</th>
                      <th scope="col">Active Threshold</th>
                      <th scope="col">Initial SOC Response</th>
                      <th scope="col">Test Rule</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr>
                      <th scope="row">DNS Flood</th>
                      <td>Single client exceeds configured queries-per-minute window</td>
                      <td>
                        &gt; {config.dns_anomaly.max_queries_per_client_per_minute} queries/min
                      </td>
                      <td>Rate-limit or investigate internal/external host</td>
                      <td>
                        <button
                          type="button"
                          className="action-btn"
                          onClick={() => void triggerSimulation('dns_flood')}
                        >
                          Simulate Flood
                        </button>
                      </td>
                    </tr>
                    <tr>
                      <th scope="row">DGA / Malware C2</th>
                      <td>Repeated NXDOMAIN (rcode=3) responses or high NXDOMAIN ratio</td>
                      <td>
                        &ge; 20 NXDOMAIN / 5m or ratio &ge;{' '}
                        {config.dns_anomaly.max_nxdomain_ratio}
                      </td>
                      <td>Block/sinkhole &amp; query reputation feeds</td>
                      <td>
                        <button
                          type="button"
                          className="action-btn"
                          onClick={() => void triggerSimulation('dga_nxdomain')}
                        >
                          Simulate DGA
                        </button>
                      </td>
                    </tr>
                    <tr>
                      <th scope="row">DNS Tunneling</th>
                      <td>High Shannon entropy on subdomain labels, long names, TXT queries</td>
                      <td>Entropy &gt; {config.dns_anomaly.high_entropy_threshold} bits</td>
                      <td>Inspect host and UDP/53 egress policy</td>
                      <td>
                        <button
                          type="button"
                          className="action-btn"
                          onClick={() => void triggerSimulation('dns_tunneling')}
                        >
                          Simulate Tunnel
                        </button>
                      </td>
                    </tr>
                    <tr>
                      <th scope="row">Suspicious TLD</th>
                      <td>Queries resolving newly registered or high-risk TLDs</td>
                      <td>.{config.dns_anomaly.suspicious_tlds.join(', .')}</td>
                      <td>Audit Zeek conn.log for subsequent HTTP/TLS connections</td>
                      <td>
                        <button
                          type="button"
                          className="action-btn"
                          onClick={() => void triggerSimulation('suspicious_tld')}
                        >
                          Simulate TLD
                        </button>
                      </td>
                    </tr>
                    <tr>
                      <th scope="row">Web Attack</th>
                      <td>Suricata EVE alert on HTTP, SQL injection, scanning, RCE</td>
                      <td>Suricata severity 1–2</td>
                      <td>Review source IP, Nginx access logs, and UFW rules</td>
                      <td>
                        <button
                          type="button"
                          className="action-btn"
                          onClick={() => void triggerSimulation('web_attack')}
                        >
                          Simulate Web Attack
                        </button>
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </section>
          )}

          {activeSection === 'ai_analyst' && (
            <section className="dashboard-section">
              <div className="tm-card-header">
                <h2 className="tm-card-title">
                  Gemini AI Threat Analyst (with LangChain HF Bucket Context)
                </h2>
                {selectedAlert && (
                  <span className="tm-pill-select">
                    Inspecting: {selectedAlert.category} ({selectedAlert.source_ip})
                  </span>
                )}
              </div>
              <div style={{ display: 'flex', gap: '0.6rem', marginBottom: '0.85rem' }}>
                <input
                  type="text"
                  value={customPrompt}
                  onChange={(e) => setCustomPrompt(e.target.value)}
                  placeholder="Ask Gemini about a DNS anomaly, Suricata rule, or UFW mitigation..."
                  style={{
                    flex: 1,
                    padding: '0.55rem 0.85rem',
                    borderRadius: '8px',
                    border: '1px solid var(--border-color)',
                    background: 'var(--bg-subtle)',
                    color: 'var(--text-primary)',
                  }}
                />
                <button
                  type="button"
                  className="action-btn primary"
                  onClick={() => void analyzeWithAi()}
                  disabled={analyzing}
                >
                  {analyzing ? 'Analyzing...' : 'Run AI Triage'}
                </button>
              </div>
              {aiAnalysis ? (
                <pre className="code-panel">{aiAnalysis}</pre>
              ) : (
                <p style={{ fontSize: '0.84rem', color: 'var(--text-muted)', margin: 0 }}>
                  Click &ldquo;Run AI Triage&rdquo; or select any alert from the Dashboard to
                  generate Ubuntu Suricata/Zeek/UFW remediation commands.
                </p>
              )}
            </section>
          )}

          {activeSection === 'hf_bucket' && (
            <div className="tm-bottom-grid">
              <section className="dashboard-section" style={{ marginBottom: 0 }}>
                <div className="tm-card-header">
                  <h2 className="tm-card-title">
                    Hugging Face Bucket (s3.hf.co) → LangChain Documents
                  </h2>
                  <span className="tm-pill-select">{datasetInfo.bucket_uri}</span>
                </div>
                <p
                  style={{
                    fontSize: '0.8rem',
                    color: 'var(--text-muted)',
                    margin: '0 0 0.5rem',
                  }}
                >
                  Source:{' '}
                  <strong
                    style={{
                      color: datasetInfo.source === 'hf-s3-bucket' ? '#10b981' : '#d97706',
                    }}
                  >
                    {datasetInfo.source ?? 'not loaded'}
                  </strong>
                  {datasetInfo.endpoint && <> • Endpoint: {datasetInfo.endpoint}</>}
                  {datasetInfo.error && <> • {datasetInfo.error}</>}
                </p>
                <pre className="code-panel">
                  {JSON.stringify(datasetInfo.documents, null, 2)}
                </pre>
              </section>

              <section className="dashboard-section" style={{ marginBottom: 0 }}>
                <div className="tm-card-header">
                  <h2 className="tm-card-title">Bucket Access (src/lib/hfBucket.ts)</h2>
                </div>
                <pre className="code-panel">{`import { S3Client, GetObjectCommand } from "@aws-sdk/client-s3";
import { FetchHttpHandler } from "@smithy/fetch-http-handler";
import { Document } from "@langchain/core/documents";

const s3 = new S3Client({
  requestHandler: new FetchHttpHandler(),
  endpoint: process.env.HF_S3_ENDPOINT,   // https://s3.hf.co/kimi-yaps
  region: "us-east-1",
  forcePathStyle: true,
  requestChecksumCalculation: "WHEN_REQUIRED",
  responseChecksumValidation: "WHEN_REQUIRED",
  credentials: {                          // from .env, never sent to browser
    accessKeyId: process.env.AWS_ACCESS_KEY_ID ?? process.env.HUGGINGFACE_API_KEY,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY ?? process.env.HUGGINGFACE_API_KEY,
  },
});`}</pre>
              </section>
            </div>
          )}
        </main>
      </div>
    </div>
  );
}

export default Home;
