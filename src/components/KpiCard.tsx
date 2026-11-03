import type { KpiCardProps } from '../types/nads';

function KpiCard({
  label,
  value,
  trendValue,
  trendDirection,
  trendLabel,
  color,
  iconSymbol,
  onActionClick,
}: KpiCardProps) {
  return (
    <article className="tm-kpi-card">
      <div className="tm-kpi-header">
        <div className="tm-kpi-title-wrap">
          <span className={`tm-kpi-dot-icon ${color}`} aria-hidden="true">
            {iconSymbol}
          </span>
          <span>{label}</span>
        </div>
        <button
          type="button"
          className="tm-kpi-dots"
          onClick={onActionClick}
          title={`Inspect ${label}`}
          aria-label={`Inspect ${label}`}
          style={{ background: 'none', border: 'none', padding: '0 0.2rem' }}
        >
          ⋮
        </button>
      </div>

      <div className="tm-kpi-value">{value}</div>

      <div className="tm-kpi-trend">
        <span className={trendDirection === 'up' ? 'tm-trend-up' : 'tm-trend-down'}>
          {trendDirection === 'up' ? '↑' : '↓'} {trendValue}
        </span>
        <span>{trendLabel}</span>
      </div>
    </article>
  );
}

export default KpiCard;

