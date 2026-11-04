import type { AnomalyAlert } from '../types/nads';

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

interface AlertsTableProps {
  title: string;
  caption: string;
  alerts: AnomalyAlert[];
  selectedAlertId?: string;
  defaultIface?: string;
  serverIp?: string;
  onSelectAlert: (alert: AnomalyAlert) => void;
  onClearAlerts?: () => void;
}

function AlertsTable({
  title,
  caption,
  alerts,
  selectedAlertId,
  defaultIface = 'ens33',
  serverIp = '192.168.150.129',
  onSelectAlert,
  onClearAlerts,
}: AlertsTableProps) {
  return (
    <section className="dashboard-section">
      <div className="tm-card-header">
        <h2 className="tm-card-title">{title}</h2>
        {onClearAlerts && (
          <div className="btn-group">
            <button type="button" className="action-btn" onClick={onClearAlerts}>
              Clear Alerts ({alerts.length})
            </button>
          </div>
        )}
      </div>

      <div
        tabIndex={0}
        role="region"
        aria-labelledby="anomalies-table-caption"
        className="table-wrapper"
      >
        <table>
          <caption id="anomalies-table-caption">{caption}</caption>
          <thead>
            <tr>
              <th scope="col">Origin IP &amp; Network</th>
              <th scope="col">Ingress / Target</th>
              <th scope="col">Attack Category</th>
              <th scope="col">Threat Score</th>
              <th scope="col">Possible Threat &amp; Trigger</th>
              <th scope="col">Time</th>
              <th scope="col">Inspect</th>
            </tr>
          </thead>
          <tbody>
            {alerts.length === 0 ? (
              <tr>
                <td colSpan={7} style={{ textAlign: 'center', color: 'var(--text-muted)' }}>
                  No active attacks detected. Live traffic on {defaultIface} ({serverIp}) is clean.
                </td>
              </tr>
            ) : (
              alerts.map((a) => {
                const info = deriveThreatAndOrigin(a, defaultIface, serverIp);
                const isSelected = selectedAlertId === a.id;
                return (
                  <tr
                    key={a.id}
                    style={
                      isSelected ? { background: 'rgba(255, 107, 0, 0.08)' } : undefined
                    }
                  >
                    <th scope="row">
                      <div>
                        <code>{a.source_ip}</code>
                      </div>
                      <div style={{ fontSize: '0.73rem', color: 'var(--text-muted)', fontWeight: 400 }}>
                        {info.originZone}
                      </div>
                    </th>
                    <td>
                      <div>
                        <code>{info.target}</code>
                      </div>
                      <div style={{ fontSize: '0.73rem', color: 'var(--text-muted)' }}>
                        via {info.iface} • {info.proto}
                      </div>
                    </td>
                    <td>
                      <span className={`severity-pill ${a.severity}`}>{a.severity}</span>{' '}
                      <span style={{ fontWeight: 600 }}>{a.category}</span>
                    </td>
                    <td>
                      <strong>{info.score}/100</strong>
                      <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                        {info.mitre.split('—')[0].trim()}
                      </div>
                    </td>
                    <td>
                      <div>{a.summary}</div>
                      <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>
                        {info.possibleThreat}
                      </div>
                    </td>
                    <td style={{ whiteSpace: 'nowrap', fontSize: '0.78rem' }}>
                      {new Date(a.timestamp).toLocaleTimeString()}
                    </td>
                    <td>
                      <button
                        type="button"
                        className="action-btn primary"
                        onClick={() => onSelectAlert(a)}
                      >
                        Assess Threat
                      </button>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}

export default AlertsTable;
