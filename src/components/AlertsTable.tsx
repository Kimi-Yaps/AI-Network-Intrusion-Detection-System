import type { AnomalyAlert } from '../types/nads';

interface AlertsTableProps {
  title: string;
  caption: string;
  alerts: AnomalyAlert[];
  analyzing: boolean;
  onAnalyzeAlert: (alert: AnomalyAlert) => void;
  onSimulate?: (scenario: string) => void;
  maxQpm?: number;
}

function AlertsTable({
  title,
  caption,
  alerts,
  analyzing,
  onAnalyzeAlert,
  onSimulate,
  maxQpm = 120,
}: AlertsTableProps) {
  return (
    <section className="dashboard-section">
      <div className="tm-card-header">
        <h2 className="tm-card-title">{title}</h2>
        {onSimulate && (
          <div className="btn-group">
            <button
              type="button"
              className="action-btn primary"
              onClick={() => onSimulate('dns_tunneling')}
            >
              + DNS Tunneling
            </button>
            <button
              type="button"
              className="action-btn"
              onClick={() => onSimulate('dga_nxdomain')}
            >
              + DGA Burst
            </button>
            <button
              type="button"
              className="action-btn"
              onClick={() => onSimulate('dns_flood')}
            >
              + DNS Flood (&gt;{maxQpm}/m)
            </button>
            <button
              type="button"
              className="action-btn"
              onClick={() => onSimulate('suspicious_tld')}
            >
              + Suspicious TLD
            </button>
            <button
              type="button"
              className="action-btn"
              onClick={() => onSimulate('web_attack')}
            >
              + Suricata Web Attack
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
              <th scope="col">Source IP</th>
              <th scope="col">Timestamp</th>
              <th scope="col">Severity</th>
              <th scope="col">Category</th>
              <th scope="col">Summary</th>
              <th scope="col">Action</th>
            </tr>
          </thead>
          <tbody>
            {alerts.map((a) => (
              <tr key={a.id}>
                <th scope="row">{a.source_ip}</th>
                <td>{a.timestamp}</td>
                <td>
                  <span className={`severity-pill ${a.severity}`}>{a.severity}</span>
                </td>
                <td>{a.category}</td>
                <td>{a.summary}</td>
                <td>
                  <button
                    type="button"
                    className="action-btn"
                    onClick={() => onAnalyzeAlert(a)}
                    disabled={analyzing}
                  >
                    AI Triage
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

export default AlertsTable;

