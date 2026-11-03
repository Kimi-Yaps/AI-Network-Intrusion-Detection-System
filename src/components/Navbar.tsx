import type { NavSectionId } from '../types/nads';

interface NavbarProps {
  activeSection: NavSectionId;
  onSelectSection: (section: NavSectionId) => void;
  searchQuery: string;
  onSearchChange: (q: string) => void;
  alertCount: number;
  serverName: string;
  connected: boolean;
}

interface NavItemConfig {
  id: NavSectionId;
  label: string;
  icon: string;
  badge?: number;
}

function Navbar({
  activeSection,
  onSelectSection,
  searchQuery,
  onSearchChange,
  alertCount,
  serverName,
  connected,
}: NavbarProps) {
  const navItems: NavItemConfig[] = [
    { id: 'dashboard', label: 'Dashboard', icon: '⊞' },
    { id: 'alerts', label: 'Live Alerts', icon: '◷', badge: alertCount },
    { id: 'dns', label: 'DNS Telemetry', icon: '◎' },
    { id: 'monitoring', label: 'Monitoring', icon: '▤' },
    { id: 'rules', label: 'Risk & Rules', icon: '⚡' },
    { id: 'ai_analyst', label: 'AI SOC Analyst', icon: '✦' },
    { id: 'hf_bucket', label: 'HF Bucket & RAG', icon: '⛁' },
    { id: 'configure', label: 'Configure', icon: '🛠' },
    { id: 'system', label: 'System', icon: '▣' },
  ];

  return (
    <aside className="tm-sidebar" aria-label="Primary Sidebar Navigation">
      <div>
        <div className="tm-brand">
          <span className="tm-logo-box" aria-hidden="true">
            N
          </span>
          <span className="tm-brand-name">NADS Guard</span>
        </div>

        <div className="tm-search-box">
          <span className="tm-search-icon" aria-hidden="true">
            🔍
          </span>
          <input
            type="search"
            className="tm-search-input"
            placeholder="Search IP, domain, rule..."
            value={searchQuery}
            onChange={(e) => onSearchChange(e.target.value)}
            aria-label="Search telemetry"
          />
        </div>

        <nav className="tm-nav-list">
          {navItems.map((item) => {
            const isActive = activeSection === item.id;
            return (
              <button
                key={item.id}
                type="button"
                className={`tm-nav-item ${isActive ? 'active' : ''}`}
                onClick={() => onSelectSection(item.id)}
              >
                <span className="tm-nav-icon" aria-hidden="true">
                  {item.icon}
                </span>
                <span>{item.label}</span>
                {typeof item.badge === 'number' && item.badge > 0 && (
                  <span className="tm-nav-badge">{item.badge}</span>
                )}
              </button>
            );
          })}
        </nav>
      </div>

      <div className="tm-user-footer">
        <div className="tm-avatar" aria-hidden="true">
          JD
        </div>
        <div className="tm-user-info">
          <div className="tm-user-name">John Doe</div>
          <div className="tm-user-role">
            {connected ? `Admin • ${serverName}` : `Local • ${serverName}`}
          </div>
        </div>
        <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }} aria-hidden="true">
          ▸
        </span>
      </div>
    </aside>
  );
}

export default Navbar;
