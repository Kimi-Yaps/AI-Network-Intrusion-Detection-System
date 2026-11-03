import type { EntityRowItem } from '../types/nads';

interface EntityListCardProps {
  title: string;
  filterLabel: string;
  items: EntityRowItem[];
  actionLabel?: string;
}

function EntityListCard({
  title,
  filterLabel,
  items,
  actionLabel,
}: EntityListCardProps) {
  return (
    <section className="dashboard-section" style={{ marginBottom: 0 }}>
      <div className="tm-card-header">
        <h2 className="tm-card-title">{title}</h2>
        <span className="tm-pill-select" style={{ padding: '0.32rem 0.7rem', fontSize: '0.75rem' }}>
          <span>{filterLabel}</span>
          <span aria-hidden="true" style={{ fontSize: '0.65rem' }}>
            ▾
          </span>
        </span>
      </div>

      <div>
        {items.map((item) => (
          <div key={item.id} className="tm-list-row">
            <div className="tm-list-left">
              <span
                className="tm-circle-badge"
                style={{ background: item.badgeColor }}
                aria-hidden="true"
              >
                {item.initials}
              </span>
              <span className="tm-list-primary">{item.primaryText}</span>
            </div>

            <span className="tm-list-secondary">{item.secondaryText}</span>

            <div className="tm-list-metric">
              <span>{item.metricText}</span>
              {item.onClick && actionLabel && (
                <button
                  type="button"
                  className="action-btn"
                  style={{ padding: '0.25rem 0.55rem', fontSize: '0.73rem' }}
                  onClick={item.onClick}
                >
                  {actionLabel}
                </button>
              )}
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}

export default EntityListCard;

