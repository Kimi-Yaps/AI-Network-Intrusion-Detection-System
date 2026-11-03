import { useState } from 'react';
import type { TelemetryPoint } from '../types/nads';

interface OverviewChartProps {
  history: TelemetryPoint[];
  totalDnsQueries: string;
  nxdomainCount: string;
  entropyRate: string;
  alertScore: string;
}

function buildPolyline(points: Array<{ x: number; y: number }>): string {
  return points.map((p) => `${p.x},${p.y}`).join(' ');
}

function scaleY(val: number, maxVal: number, topY = 28, bottomY = 192): number {
  const safeMax = Math.max(maxVal, 1);
  const ratio = Math.min(Math.max(val / safeMax, 0), 1);
  return Math.round(bottomY - ratio * (bottomY - topY));
}

function OverviewChart({
  history,
  totalDnsQueries,
  nxdomainCount,
  entropyRate,
  alertScore,
}: OverviewChartProps) {
  const [hoverIdx, setHoverIdx] = useState<number | null>(null);

  const series: TelemetryPoint[] =
    history.length >= 2
      ? history
      : [
          {
            timestamp: new Date(Date.now() - 2000).toLocaleTimeString('en-US', { hour12: false }),
            qpm: 0,
            nxdomain: 0,
            entropy: 0,
            alerts: 0,
          },
          {
            timestamp: new Date().toLocaleTimeString('en-US', { hour12: false }),
            qpm: 0,
            nxdomain: 0,
            entropy: 0,
            alerts: 0,
          },
        ];

  const maxQpm = Math.max(...series.map((p) => p.qpm), 50);
  const maxNx = Math.max(...series.map((p) => p.nxdomain), 20);
  const maxAlerts = Math.max(...series.map((p) => p.alerts), 10);

  const count = series.length;
  const chartPoints = series.map((pt, idx) => {
    const x = Math.round(25 + (idx / Math.max(count - 1, 1)) * 770);
    return {
      ...pt,
      x,
      blueY: scaleY(pt.qpm, maxQpm, 30, 188),
      greenY: scaleY(pt.alerts, maxAlerts, 50, 190),
      orangeY: scaleY(pt.entropy, 5.0, 60, 192),
      yellowY: scaleY(pt.nxdomain, maxNx, 70, 194),
    };
  });

  const activeIdx =
    hoverIdx !== null && hoverIdx < chartPoints.length ? hoverIdx : chartPoints.length - 1;
  const currentPoint = chartPoints[activeIdx];

  const bluePoints = buildPolyline(chartPoints.map((p) => ({ x: p.x, y: p.blueY })));
  const greenPoints = buildPolyline(chartPoints.map((p) => ({ x: p.x, y: p.greenY })));
  const orangePoints = buildPolyline(chartPoints.map((p) => ({ x: p.x, y: p.orangeY })));
  const yellowPoints = buildPolyline(chartPoints.map((p) => ({ x: p.x, y: p.yellowY })));

  return (
    <section className="dashboard-section" aria-label="Network & DNS Telemetry Overview">
      <div className="tm-card-header">
        <h2 className="tm-card-title">Live Telemetry Overview</h2>

        <div className="tm-legend-list">
          <span className="tm-legend-item">
            <span className="tm-legend-dot" style={{ background: '#2563eb' }} />
            DNS Volume ({totalDnsQueries})
          </span>
          <span className="tm-legend-item">
            <span className="tm-legend-dot" style={{ background: '#f59e0b' }} />
            NXDOMAIN ({nxdomainCount})
          </span>
          <span className="tm-legend-item">
            <span className="tm-legend-dot" style={{ background: '#ff6b00' }} />
            Entropy ({entropyRate})
          </span>
          <span className="tm-legend-item">
            <span className="tm-legend-dot" style={{ background: '#10b981' }} />
            Active Alerts ({alertScore})
          </span>
        </div>
      </div>

      <div className="tm-chart-wrap" onMouseLeave={() => setHoverIdx(null)}>
        <svg
          className="tm-chart-svg"
          viewBox="0 0 820 230"
          preserveAspectRatio="none"
          role="img"
          aria-label="Live multi-line telemetry time series chart"
        >
          <defs>
            <linearGradient id="tmBlueGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#2563eb" stopOpacity="0.14" />
              <stop offset="100%" stopColor="#2563eb" stopOpacity="0.0" />
            </linearGradient>
            <linearGradient id="tmGreenGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#10b981" stopOpacity="0.1" />
              <stop offset="100%" stopColor="#10b981" stopOpacity="0.0" />
            </linearGradient>
          </defs>

          {[35, 75, 115, 155, 195].map((y) => (
            <line key={y} x1="15" y1={y} x2="805" y2={y} stroke="#f1f5f9" strokeWidth="1" />
          ))}

          <polygon points={`25,195 ${bluePoints} 795,195`} fill="url(#tmBlueGrad)" />
          <polygon points={`25,195 ${greenPoints} 795,195`} fill="url(#tmGreenGrad)" />

          <polyline
            fill="none"
            stroke="#2563eb"
            strokeWidth="2"
            strokeLinejoin="round"
            strokeLinecap="round"
            points={bluePoints}
          />
          <polyline
            fill="none"
            stroke="#10b981"
            strokeWidth="2"
            strokeLinejoin="round"
            strokeLinecap="round"
            points={greenPoints}
          />
          <polyline
            fill="none"
            stroke="#ff6b00"
            strokeWidth="2"
            strokeLinejoin="round"
            strokeLinecap="round"
            points={orangePoints}
          />
          <polyline
            fill="none"
            stroke="#eab308"
            strokeWidth="2"
            strokeLinejoin="round"
            strokeLinecap="round"
            points={yellowPoints}
          />

          <line
            x1={currentPoint.x}
            y1="15"
            x2={currentPoint.x}
            y2="195"
            stroke="#94a3b8"
            strokeWidth="1.3"
            strokeDasharray="4 4"
          />

          <circle
            cx={currentPoint.x}
            cy={currentPoint.blueY}
            r="4.5"
            fill="#ffffff"
            stroke="#2563eb"
            strokeWidth="2"
          />

          {chartPoints.map((pt, idx) => (
            <rect
              key={`${pt.timestamp}-${idx}`}
              x={pt.x - 20}
              y="10"
              width="40"
              height="190"
              fill="transparent"
              style={{ cursor: 'pointer' }}
              onMouseEnter={() => setHoverIdx(idx)}
            />
          ))}

          {chartPoints.map((pt, idx) => {
            const step = Math.max(1, Math.floor(chartPoints.length / 6));
            if (idx % step !== 0 && idx !== chartPoints.length - 1) return null;
            return (
              <text
                key={`lbl-${pt.timestamp}-${idx}`}
                x={pt.x}
                y="220"
                fill="#94a3b8"
                fontSize="11"
                textAnchor="middle"
              >
                {pt.timestamp}
              </text>
            );
          })}
        </svg>

        <div
          className="tm-chart-tooltip"
          style={{
            left: `clamp(16px, calc(${(currentPoint.x / 820) * 100}% - 80px), calc(100% - 175px))`,
          }}
        >
          <div className="tm-tooltip-date">Live • {currentPoint.timestamp}</div>
          <div className="tm-tooltip-row">
            <span className="tm-kpi-dot-icon blue" style={{ width: 15, height: 15, fontSize: 9 }}>
              ●
            </span>
            <span>{currentPoint.qpm} queries/m</span>
          </div>
          <div className="tm-tooltip-row">
            <span className="tm-kpi-dot-icon yellow" style={{ width: 15, height: 15, fontSize: 9 }}>
              ●
            </span>
            <span>{currentPoint.nxdomain} NXDOMAIN</span>
          </div>
          <div className="tm-tooltip-row">
            <span className="tm-kpi-dot-icon orange" style={{ width: 15, height: 15, fontSize: 9 }}>
              ●
            </span>
            <span>{currentPoint.entropy} bits</span>
          </div>
          <div className="tm-tooltip-row">
            <span className="tm-kpi-dot-icon green" style={{ width: 15, height: 15, fontSize: 9 }}>
              ●
            </span>
            <span>{currentPoint.alerts} alerts</span>
          </div>
        </div>
      </div>
    </section>
  );
}

export default OverviewChart;
