import { deriveThreatAndOrigin, type AnomalyAlert } from '../types/nads';

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
