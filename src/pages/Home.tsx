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

const PRIMARY_API = import.meta.env.VITE_API_URL || 'http://localhost:8000';
const SECONDARY_API = 'http://localhost:3001';

const DEFAULT_CONFIG: ServerConfig = {
  config_path: '/etc/nads/config.yaml',
  using_system_etc_config: false,
  server: {
    name: 'JB-Web-Server-01',
    environment: 'production',
    listen_interface: 'eth0',
    public_ip: '203.0.113.10',
    os: 'Ubuntu 24.04 LTS',
  },
  web: {
    react_app_url: 'https://nads.example.com',
    api_url: 'https://nads.example.com/api',
    allowed_origins: ['https://nads.example.com', 'http://localhost:5173'],
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
    provider: 'gcs',
    bucket_uri: 'gs://nads-security-lake/hf-datasets/cicids-dns',
    hf_dataset_id: 'Mandatory/Cybersecurity-Attack-Dataset',
    split: 'train',
    streaming: true,
  },
};

const DEFAULT_ALERTS: AnomalyAlert[] = [
  {
    id: 'seed-1',
    timestamp: new Date().toISOString(),
    severity: 'high',
    category: 'Possible DNS tunneling',
    source_ip: '10.0.14.88',
    summary:
      'High-entropy DNS label (3.96 bits): 4f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c.x91k2m.c2-tunnel.net',
    evidence: {
      entropy: 3.96,
      query: '4f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c.x91k2m.c2-tunnel.net',
      rrtype: 'TXT',
    },
  },
  {
    id: 'seed-2',
    timestamp: new Date(Date.now() - 45000).toISOString(),
    severity: 'high',
    category: 'IDS signature',
    source_ip: '198.51.100.42',
    summary: 'ET WEB_SERVER SQL Injection Attempt in URI (UNION SELECT)',
    evidence: {
      proto: 'TCP',
      dest_ip: '203.0.113.10',
      signature_severity: 1,
    },
  },
  {
    id: 'seed-3',
    timestamp: new Date(Date.now() - 95000).toISOString(),
    severity: 'medium',
    category: 'Suspicious TLD',
    source_ip: '10.0.14.23',
    summary: 'Query to monitored suspicious TLD (.zip): invoice-update-auth-portal.zip',
    evidence: {
      tld: 'zip',
      query: 'invoice-update-auth-portal.zip',
      rrtype: 'A',
    },
  },
];

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
  const [activeApi, setActiveApi] = useState<string>(PRIMARY_API);
  const [connected, setConnected] = useState<boolean>(false);
  const [activeSection, setActiveSection] = useState<NavSectionId>('dashboard');
  const [searchQuery, setSearchQuery] = useState<string>('');

  const [config, setConfig] = useState<ServerConfig>(DEFAULT_CONFIG);
  const [status, setStatus] = useState<ServerStatus>({
    server_name: DEFAULT_CONFIG.server.name,
    environment: DEFAULT_CONFIG.server.environment,
    public_ip: DEFAULT_CONFIG.server.public_ip,
    interface: DEFAULT_CONFIG.server.listen_interface,
    config_path: DEFAULT_CONFIG.config_path,
    suricata_log_exists: false,
    zeek_dns_log_exists: false,
    active_alerts: DEFAULT_ALERTS.length,
    tracked_dns_clients: 3,
    client_query_rates: { '10.0.14.88': 94, '198.51.100.42': 61, '10.0.14.23': 38 },
  });
  const [alerts, setAlerts] = useState<AnomalyAlert[]>(DEFAULT_ALERTS);
  const [datasetInfo, setDatasetInfo] = useState<LangChainDatasetPayload>({
    bucket_uri: 'gs://nads-security-lake/hf-datasets/cicids-dns',
    provider: 'gcs',
    hf_dataset_id: 'Mandatory/Cybersecurity-Attack-Dataset',
    document_count: 3,
    documents: [
      {
        page_content: JSON.stringify({
          attack_type: 'DNS Tunneling (Iodine / DNScat2)',
          indicator: 'Subdomain Shannon entropy > 3.8 bits, TXT/NULL flood',
          mitigation: 'Inspect host egress on UDP/53, block C2 domain in resolver',
        }),
        metadata: {
          dataset: 'Mandatory/Cybersecurity-Attack-Dataset',
          bucket_uri: 'gs://nads-security-lake/hf-datasets/cicids-dns',
          row_idx: 0,
        },
      },
    ],
  });

  // Editable DNS threshold state
  const [maxQpm, setMaxQpm] = useState<number>(120);
  const [maxNxRatio, setMaxNxRatio] = useState<number>(0.5);
  const [entropyThreshold, setEntropyThreshold] = useState<number>(3.5);
  const [tldsInput, setTldsInput] = useState<string>('zip, mov, top, xyz');
  const [configSaveMsg, setConfigSaveMsg] = useState<string>('');

  // AI Analyst state
  const [selectedAlert, setSelectedAlert] = useState<AnomalyAlert | null>(null);
  const [customPrompt, setCustomPrompt] = useState<string>('');
  const [aiAnalysis, setAiAnalysis] = useState<string>('');
  const [analyzing, setAnalyzing] = useState<boolean>(false);

  const loadTelemetry = useCallback(async () => {
    const candidates = [PRIMARY_API, SECONDARY_API];
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
          setMaxQpm(cData.dns_anomaly.max_queries_per_client_per_minute);
          setMaxNxRatio(cData.dns_anomaly.max_nxdomain_ratio);
          setEntropyThreshold(cData.dns_anomaly.high_entropy_threshold);
          setTldsInput((cData.dns_anomaly.suspicious_tlds || []).join(', '));
          setActiveApi(base);
          setConnected(true);
          return;
        }
      } catch {
        // try next candidate
      }
    }
    setConnected(false);
  }, []);

  useEffect(() => {
    const initial = setTimeout(() => {
      void loadTelemetry();
    }, 0);
    const timer = setInterval(() => {
      void loadTelemetry();
    }, 5000);
    return () => {
      clearTimeout(initial);
      clearInterval(timer);
    };
  }, [loadTelemetry]);

  const triggerSimulation = async (scenario: string) => {
    if (connected) {
      try {
        await fetch(`${activeApi}/api/simulate`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ scenario }),
        });
        await loadTelemetry();
        return;
      } catch {
        // fall through to local simulation
      }
    }

    const nowIso = new Date().toISOString();
    const simulatedMap: Record<string, AnomalyAlert> = {
      dns_tunneling: {
        id: `sim-${Date.now()}`,
        timestamp: nowIso,
        severity: 'high',
        category: 'Possible DNS tunneling',
        source_ip: '10.0.14.88',
        summary:
          'High-entropy DNS label (4.02 bits): a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4.k8z9q1w2e3r4.exfil-c2.org',
        evidence: {
          entropy: 4.02,
          rrtype: 'TXT',
          query: 'a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4.k8z9q1w2e3r4.exfil-c2.org',
        },
      },
      dga_nxdomain: {
        id: `sim-${Date.now()}`,
        timestamp: nowIso,
        severity: 'medium',
        category: 'Possible DGA',
        source_ip: '10.0.14.105',
        summary: 'Repeated NXDOMAIN responses from 10.0.14.105 (21 in 5m)',
        evidence: { recent_nxdomain: 21, nxdomain_ratio: 0.84, query: 'q20x8k9m2v7p4n20.biz' },
      },
      dns_flood: {
        id: `sim-${Date.now()}`,
        timestamp: nowIso,
        severity: 'high',
        category: 'DNS volume',
        source_ip: '10.0.14.210',
        summary: `High DNS query volume: ${maxQpm + 18} queries/minute (threshold: ${maxQpm})`,
        evidence: { queries_per_minute: maxQpm + 18, query: 'api-lookup.internal.example.com' },
      },
      suspicious_tld: {
        id: `sim-${Date.now()}`,
        timestamp: nowIso,
        severity: 'medium',
        category: 'Suspicious TLD',
        source_ip: '10.0.14.54',
        summary: 'Query to monitored suspicious TLD (.xyz): credential-harvest-login.xyz',
        evidence: { tld: 'xyz', query: 'credential-harvest-login.xyz' },
      },
      web_attack: {
        id: `sim-${Date.now()}`,
        timestamp: nowIso,
        severity: 'high',
        category: 'IDS signature',
        source_ip: '203.0.113.244',
        summary: 'ET WEB_SERVER Possible CVE-2024 Remote Command Execution Attempt',
        evidence: { proto: 'TCP', dest_ip: config.server.public_ip, severity: 1 },
      },
    };
    const nextAlert = simulatedMap[scenario];
    if (nextAlert) {
      setAlerts((prev) => [nextAlert, ...prev]);
      setStatus((prev) => ({ ...prev, active_alerts: prev.active_alerts + 1 }));
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

    if (connected) {
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
        // fallback below
      }
    }
    setConfig((prev) => ({ ...prev, dns_anomaly: payload }));
    setConfigSaveMsg('Updated local session configuration.');
  };

  const analyzeWithAi = async (alertToInspect?: AnomalyAlert) => {
    const target = alertToInspect || selectedAlert || alerts[0];
    if (alertToInspect) {
      setSelectedAlert(alertToInspect);
      setActiveSection('ai_analyst');
    }
    setAnalyzing(true);
    setAiAnalysis('');

    if (connected) {
      try {
        const res = await fetch(`${activeApi}/api/analyze`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            alert_id: target?.id,
            prompt:
              customPrompt.trim() ||
              `Analyze this ${target?.category} alert from ${target?.source_ip} (${target?.summary}) correlated with our Hugging Face bucket dataset and provide Ubuntu/Suricata/Zeek mitigation steps.`,
          }),
        });
        const data = await res.json();
        setAiAnalysis(data.text || data.detail || data.error || 'No analysis returned.');
        setAnalyzing(false);
        return;
      } catch {
        // fallback explanation if backend is offline
      }
    }

    setAiAnalysis(
      `[Offline SOC Triage — Start backend on port 8000 for live Gemini 3.8 Flash + LangChain analysis]\n\n` +
      `Target Alert: ${target?.category} (${target?.severity.toUpperCase()})\n` +
      `Source IP: ${target?.source_ip}\n` +
      `Summary: ${target?.summary}\n\n` +
      `Recommended Ubuntu Verification Commands:\n` +
      `1. Inspect Suricata EVE JSON:\n` +
      `   sudo jq 'select(.src_ip=="${target?.source_ip}")' ${config.monitoring.suricata_eve_path}\n` +
      `2. Inspect Zeek DNS Log:\n` +
      `   cat ${config.monitoring.zeek_log_dir}/dns.log | zeek-cut ts id.orig_h query qtype_name rcode_name | grep "${target?.source_ip}"\n` +
      `3. Block or Rate-Limit Offending Host via UFW:\n` +
      `   sudo ufw insert 1 deny from ${target?.source_ip} to any`
    );
    setAnalyzing(false);
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

  const kpiCards: KpiCardProps[] = [
    {
      label: 'DNS Queries',
      value: '1,039/m',
      trendValue: '20%',
      trendDirection: 'up',
      trendLabel: `limit ${config.dns_anomaly.max_queries_per_client_per_minute}/m`,
      color: 'blue',
      iconSymbol: '◷',
      onActionClick: () => setActiveSection('dns'),
    },
    {
      label: 'NXDOMAIN / DGA',
      value: '21h',
      trendValue: '10%',
      trendDirection: 'down',
      trendLabel: `max ratio ${config.dns_anomaly.max_nxdomain_ratio}`,
      color: 'yellow',
      iconSymbol: '⚑',
      onActionClick: () => triggerSimulation('dga_nxdomain'),
    },
    {
      label: 'Entropy Ratio',
      value: '40%',
      trendValue: '20%',
      trendDirection: 'up',
      trendLabel: `threshold ${config.dns_anomaly.high_entropy_threshold}b`,
      color: 'orange',
      iconSymbol: '⚡',
      onActionClick: () => triggerSimulation('dns_tunneling'),
    },
    {
      label: 'Active Alerts',
      value: `${alerts.length} Alerts`,
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
      metricText: status.suricata_log_exists ? 'LIVE' : 'SIMULATED',
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

          {/* 4 Reusable KPI Cards Row */}
          <section className="tm-kpi-row" aria-label="Key Security Metrics">
            {kpiCards.map((card) => (
              <KpiCard key={card.label} {...card} />
            ))}
          </section>

          {activeSection === 'dashboard' && (
            <>
              <OverviewChart
                totalDnsQueries="1,039/m"
                nxdomainCount="21 NX"
                entropyRate="3.96 bits"
                alertScore={`${alerts.length} Alerts`}
              />

              <div className="tm-bottom-grid">
                <EntityListCard
                  title="Top Source IPs"
                  filterLabel="By threat severity"
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
                title="Recent Network & DNS Anomalies"
                caption={`Live telemetry ingested for ${status.server_name} (${config.server.public_ip})`}
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

          {(activeSection === 'configure' ||
            activeSection === 'monitoring' ||
            activeSection === 'system') && (
              <div className="tm-bottom-grid">
                <section className="dashboard-section" style={{ marginBottom: 0 }}>
                  <div className="tm-card-header">
                    <h2 className="tm-card-title">
                      Server Configuration ({config.config_path || '/etc/nads/config.yaml'})
                    </h2>
                  </div>
                  <pre className="code-panel">{JSON.stringify(config, null, 2)}</pre>
                </section>

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
                    }}
                  >
                    <button
                      type="button"
                      className="action-btn primary"
                      onClick={() => void handleSaveDnsConfig()}
                    >
                      Save to Server Config
                    </button>
                    {configSaveMsg && (
                      <span style={{ fontSize: '0.82rem', color: '#10b981', fontWeight: 600 }}>
                        {configSaveMsg}
                      </span>
                    )}
                  </div>
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
                <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', margin: '0 0 0.5rem' }}>
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
                  <h2 className="tm-card-title">
                    Bucket Access (src/lib/hfBucket.ts)
                  </h2>
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
});

const obj = await s3.send(new GetObjectCommand({
  Bucket: process.env.HF_S3_BUCKET,
  Key: process.env.HF_S3_KEY,
}));
const text = await obj.Body.transformToString();

// .jsonl/.json/.csv -> one Document per row, otherwise text chunks
const docs = textToDocuments(text, key, settings);`}</pre>
              </section>
            </div>
          )}
        </main>
      </div>
    </div>
  );
}

export default Home;
