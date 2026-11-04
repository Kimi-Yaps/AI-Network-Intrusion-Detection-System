import type { AnomalyAlert } from '../types/nads';

interface AlertsTableProps {
  title: string;
  caption: string;
  alerts: AnomalyAlert[];
  analyzing: boolean;
  onAnalyzeAlert: (alert: AnomalyAlert) => void;
  onClearAlerts?: () => void;
}

function AlertsTable({
  title,
  caption,
  alerts,
  analyzing,
  onAnalyzeAlert,
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

