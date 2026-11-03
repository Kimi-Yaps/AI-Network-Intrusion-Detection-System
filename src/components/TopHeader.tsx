interface TopHeaderProps {
  title: string;
  serverName: string;
  interfaceName: string;
  connected: boolean;
  onRefresh: () => void;
  onOpenSettings: () => void;
}

function TopHeader({
  title,
  serverName,
  interfaceName,
  connected,
  onRefresh,
  onOpenSettings,
}: TopHeaderProps) {
  return (
    <header className="tm-topbar">
      <h1 className="tm-page-title">{title}</h1>

      <div className="tm-topbar-controls">
        <button
          type="button"
          className="tm-pill-select"
          onClick={onRefresh}
          title="Click to refresh telemetry from server"
          style={{ cursor: 'pointer' }}
        >
          <span aria-hidden="true">📅</span>
          <span>
            {serverName} ({interfaceName}) • {connected ? 'Live' : 'Demo'}
          </span>
          <span aria-hidden="true" style={{ marginLeft: '0.25rem', fontSize: '0.7rem' }}>
            ▾
          </span>
        </button>

        <button
          type="button"
          className="tm-icon-btn"
          onClick={onOpenSettings}
          title="Configure /etc/nads/config.yaml"
          aria-label="Open server configuration"
        >
          ⚙
        </button>
      </div>
    </header>
  );
}

export default TopHeader;

