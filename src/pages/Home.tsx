import { useCallback, useEffect, useMemo, useState } from 'react';
import AlertsTable from '../components/AlertsTable';
import EntityListCard from '../components/EntityListCard';
import KpiCard from '../components/KpiCard';
import Navbar from '../components/Navbar';
import OverviewChart from '../components/OverviewChart';
import TopHeader from '../components/TopHeader';
import {
  deriveThreatAndOrigin,
  type AnomalyAlert,
  type EntityRowItem,
  type KpiCardProps,
  type LangChainDatasetPayload,
  type NavSectionId,
  type ServerConfig,
  type ServerStatus,
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
  alerts: 'Attacks, Threat Assessment & Origin Trace',
  configure: 'Detection Rules & Threshold Configuration',
  hf_bucket: 'Hugging Face Bucket & LangChain RAG',
  system: 'Ubuntu System & Sensor Health',
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

  // Threat Assessment & AI Analyst state
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

  const clearAllAlerts = async () => {
    try {
      await fetch(`${activeApi}/api/alerts`, { method: 'DELETE' });
      setAlerts([]);
      setSelectedAlert(null);
      setAiAnalysis('');
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

  const buildLocalThreatReport = (target?: AnomalyAlert | null) => {
    if (!target) {
      return 'No active attack selected. Select any attack row from the table to inspect its threat score and origin.';
    }
    const info = deriveThreatAndOrigin(
      target,
      status.interface || 'ens33',
      config.server.public_ip || '192.168.150.129'
    );
    return [
      `=== NADS THREAT SCORE & ORIGIN ASSESSMENT ===`,
      `• Threat Score      : ${info.score}/100 (${target.severity.toUpperCase()} RISK)`,
      `• Attack Category   : ${target.category}`,
      `• MITRE ATT&CK      : ${info.mitre}`,
      `• Trigger Summary   : ${target.summary}`,
      ``,
      `=== WHERE IT ORIGINATED FROM ===`,
      `• Source IP         : ${target.source_ip}`,
      `• Network Origin    : ${info.originZone}`,
      `• Ingress Path      : ${info.iface} -> ${info.target} (${info.proto})`,
      `• Assessment        : ${info.possibleThreat}`,
      ``,
      `=== RECOMMENDED UBUNTU MITIGATION ===`,
      info.remediationCmd,
    ].join('\n');
  };

  const inspectAndAnalyzeAlert = async (alertToInspect?: AnomalyAlert) => {
    const target = alertToInspect || selectedAlert || alerts[0] || null;
    if (alertToInspect) {
      setSelectedAlert(alertToInspect);
      setActiveSection('alerts');
    }
    setAnalyzing(true);
    setAiAnalysis(buildLocalThreatReport(target));

    try {
      const res = await fetch(`${activeApi}/api/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          alert_id: target?.id,
          prompt:
            customPrompt.trim() ||
            `Score this ${target?.category || 'network'} threat from ${target?.source_ip || 'host'}, trace its origin, and provide Ubuntu/Suricata/UFW mitigation steps.`,
        }),
      });
      if (res.ok) {
        const data = await res.json();
        if (data.text) {
          setAiAnalysis(data.text);
        }
      }
    } catch {
      // Keep the instant deterministic threat & origin assessment displayed
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

  const activeInspectedAlert = selectedAlert || filteredAlerts[0] || null;
  const activeThreatInfo = activeInspectedAlert
    ? deriveThreatAndOrigin(
        activeInspectedAlert,
        status.interface || 'ens33',
        config.server.public_ip || '192.168.150.129'
      )
    : null;

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
      onActionClick: () => setActiveSection('alerts'),
    },
    {
      label: 'NXDOMAIN (5m)',
      value: `${liveNx}`,
      trendValue: liveNx >= 20 ? 'DGA Risk' : 'Normal',
      trendDirection: liveNx >= 20 ? 'up' : 'down',
      trendLabel: `max ratio ${config.dns_anomaly.max_nxdomain_ratio}`,
      color: 'yellow',
      iconSymbol: '⚑',
      onActionClick: () => setActiveSection('alerts'),
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
      onActionClick: () => setActiveSection('alerts'),
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
  const topSourceIpItems: EntityRowItem[] = filteredAlerts.slice(0, 4).map((alert, idx) => {
    const info = deriveThreatAndOrigin(
      alert,
      status.interface || 'ens33',
      config.server.public_ip || '192.168.150.129'
    );
    return {
      id: `src-${alert.id}`,
      initials: alert.source_ip.split('.').slice(-1)[0] || 'IP',
      badgeColor: palette[idx % palette.length],
      primaryText: `${alert.source_ip} (${info.originZone.split('(')[0].trim()})`,
      secondaryText: `${alert.category} → ${info.target}`,
      metricText: `${info.score}/100`,
      onClick: () => void inspectAndAnalyzeAlert(alert),
    };
  });

  const topSensorDepartments: EntityRowItem[] = [
    {
      id: 'dep-suricata',
      initials: 'SR',
      badgeColor: '#ff6b00',
      primaryText: 'Suricata EVE Sensor',
      secondaryText: config.monitoring.suricata_eve_path,
      metricText: status.suricata_log_exists ? 'LIVE' : 'WAITING',
      onClick: () => setActiveSection('alerts'),
    },
    {
      id: 'dep-zeek',
      initials: 'ZK',
      badgeColor: '#2563eb',
      primaryText: 'Active DNS Clients',
      secondaryText: `Monitored on ${status.interface}`,
      metricText: `${status.tracked_dns_clients} hosts`,
      onClick: () => setActiveSection('alerts'),
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
      primaryText: 'Detection Rules & Config',
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
                  title="Top Attacking Origins"
                  filterLabel="Source IP & Threat Score"
                  items={topSourceIpItems}
                  actionLabel="Assess"
                />

                <EntityListCard
                  title="Active Sensors & Config"
                  filterLabel="By subsystem"
                  items={topSensorDepartments}
                  actionLabel="Open"
                />
              </div>

              <AlertsTable
                title="All Detected Attacks & Origin Trace"
                caption={`Live telemetry from ${status.server_name} (${config.server.public_ip}) on ${status.interface}`}
                alerts={filteredAlerts}
                selectedAlertId={activeInspectedAlert?.id}
                defaultIface={status.interface}
                serverIp={config.server.public_ip}
                onSelectAlert={(a) => void inspectAndAnalyzeAlert(a)}
                onClearAlerts={() => void clearAllAlerts()}
              />
            </>
          )}

          {activeSection === 'alerts' && (
            <>
              <AlertsTable
                title="All Detected Attacks & Origin Trace"
                caption="Click 'Assess Threat' on any attack row to inspect its origin path, threat score, MITRE mapping, and remediation."
                alerts={filteredAlerts}
                selectedAlertId={activeInspectedAlert?.id}
                defaultIface={status.interface}
                serverIp={config.server.public_ip}
                onSelectAlert={(a) => void inspectAndAnalyzeAlert(a)}
                onClearAlerts={() => void clearAllAlerts()}
              />

              <div className="tm-bottom-grid">
                <section className="dashboard-section" style={{ marginBottom: 0 }}>
                  <div className="tm-card-header">
                    <h2 className="tm-card-title">Possible Threat &amp; Origin Inspector</h2>
                    {activeInspectedAlert && activeThreatInfo && (
                      <span className={`severity-pill ${activeInspectedAlert.severity}`}>
                        Score: {activeThreatInfo.score}/100 ({activeInspectedAlert.severity})
                      </span>
                    )}
                  </div>

                  {!activeInspectedAlert || !activeThreatInfo ? (
                    <p style={{ fontSize: '0.84rem', color: 'var(--text-muted)', margin: 0 }}>
                      No active attacks in the table. When Suricata or the DNS behavioral engine
                      detects an attack, its origin and threat score will appear here automatically.
                    </p>
                  ) : (
                    <div className="config-form-grid" style={{ gap: '0.7rem' }}>
                      <div>
                        <strong>Origin IP:</strong> <code>{activeInspectedAlert.source_ip}</code>
                      </div>
                      <div>
                        <strong>Origin Network Zone:</strong> {activeThreatInfo.originZone}
                      </div>
                      <div>
                        <strong>Ingress Path &amp; Target:</strong>{' '}
                        <code>
                          {activeThreatInfo.iface} → {activeThreatInfo.target} (
                          {activeThreatInfo.proto})
                        </code>
                      </div>
                      <div>
                        <strong>Attack Category:</strong> {activeInspectedAlert.category}
                      </div>
                      <div style={{ gridColumn: '1 / -1' }}>
                        <strong>MITRE ATT&amp;CK:</strong> {activeThreatInfo.mitre}
                      </div>
                      <div style={{ gridColumn: '1 / -1' }}>
                        <strong>Possible Threat Assessment:</strong>{' '}
                        {activeThreatInfo.possibleThreat}
                      </div>
                      <div style={{ gridColumn: '1 / -1' }}>
                        <strong>Ubuntu Mitigation Command:</strong>
                        <pre className="code-panel" style={{ marginTop: '0.35rem' }}>
                          {activeThreatInfo.remediationCmd}
                        </pre>
                      </div>
                    </div>
                  )}
                </section>

                <section className="dashboard-section" style={{ marginBottom: 0 }}>
                  <div className="tm-card-header">
                    <h2 className="tm-card-title">AI &amp; LangChain Threat Scoring</h2>
                    {activeInspectedAlert && (
                      <span className="tm-pill-select">
                        {activeInspectedAlert.source_ip} • {activeInspectedAlert.category}
                      </span>
                    )}
                  </div>
                  <div style={{ display: 'flex', gap: '0.6rem', marginBottom: '0.85rem' }}>
                    <input
                      type="text"
                      value={customPrompt}
                      onChange={(e) => setCustomPrompt(e.target.value)}
                      placeholder="Ask about this threat score, origin IP, or mitigation..."
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
                      onClick={() => void inspectAndAnalyzeAlert(activeInspectedAlert || undefined)}
                      disabled={analyzing}
                    >
                      {analyzing ? 'Scoring...' : 'Score & Analyze'}
                    </button>
                  </div>
                  <pre className="code-panel">
                    {aiAnalysis || buildLocalThreatReport(activeInspectedAlert)}
                  </pre>
                </section>
              </div>

              <section className="dashboard-section" style={{ marginTop: '1rem' }}>
                <div className="tm-card-header">
                  <h2 className="tm-card-title">
                    Live DNS Query Stream ({config.monitoring.suricata_eve_path})
                  </h2>
                  <span className="tm-pill-select">
                    {(status.recent_dns_queries ?? []).length} recent queries
                  </span>
                </div>
                <div
                  className="table-wrapper"
                  tabIndex={0}
                  role="region"
                  aria-label="Live DNS Queries"
                >
                  <table>
                    <thead>
                      <tr>
                        <th scope="col">Time</th>
                        <th scope="col">Origin Client IP</th>
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
                          <td
                            colSpan={7}
                            style={{ textAlign: 'center', color: 'var(--text-muted)' }}
                          >
                            No live DNS queries captured yet.
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
            </>
          )}

          {activeSection === 'configure' && (
            <>
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
                      onClick={() => void clearAllAlerts()}
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

              <section className="dashboard-section" style={{ marginTop: '1rem' }}>
                <div className="tm-card-header">
                  <h2 className="tm-card-title">
                    Active Detection Rules Matrix (Suricata EVE + DNS Behavioral Engine)
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
                      </tr>
                      <tr>
                        <th scope="row">DGA / Malware C2</th>
                        <td>Repeated NXDOMAIN (rcode=3) responses or high NXDOMAIN ratio</td>
                        <td>
                          &ge; 20 NXDOMAIN / 5m or ratio &ge;{' '}
                          {config.dns_anomaly.max_nxdomain_ratio}
                        </td>
                        <td>Block/sinkhole &amp; query reputation feeds</td>
                      </tr>
                      <tr>
                        <th scope="row">DNS Tunneling</th>
                        <td>High Shannon entropy on subdomain labels, long names, TXT queries</td>
                        <td>Entropy &gt; {config.dns_anomaly.high_entropy_threshold} bits</td>
                        <td>Inspect host and UDP/53 egress policy</td>
                      </tr>
                      <tr>
                        <th scope="row">Suspicious TLD</th>
                        <td>Queries resolving newly registered or high-risk TLDs</td>
                        <td>.{config.dns_anomaly.suspicious_tlds.join(', .')}</td>
                        <td>Audit subsequent HTTP/TLS connections from source IP</td>
                      </tr>
                      <tr>
                        <th scope="row">Web / Network Intrusion</th>
                        <td>Suricata EVE alert on port scans, exploits, SQLi, or RCE</td>
                        <td>Suricata severity 1–3 (excluding stream noise)</td>
                        <td>Review source IP and block via UFW</td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </section>
            </>
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
