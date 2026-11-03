import { useState } from 'react';

interface OverviewChartProps {
  totalDnsQueries: string;
  nxdomainCount: string;
  entropyRate: string;
  alertScore: string;
}

interface TimePoint {
  dateLabel: string;
  x: number;
  blueY: number;
  greenY: number;
  orangeY: number;
  yellowY: number;
  qpm: string;
  nx: string;
  entropy: string;
  alertsVal: string;
}

const CHART_POINTS: TimePoint[] = [
  { dateLabel: '07 Jul', x: 20, blueY: 72, greenY: 122, orangeY: 162, yellowY: 192, qpm: '1,120/m', nx: '14', entropy: '3.2b', alertsVal: '2' },
  { dateLabel: '09 Jul', x: 80, blueY: 54, greenY: 146, orangeY: 158, yellowY: 190, qpm: '1,240/m', nx: '16', entropy: '3.4b', alertsVal: '3' },
  { dateLabel: '11 Jul', x: 140, blueY: 108, greenY: 128, orangeY: 168, yellowY: 191, qpm: '910/m', nx: '12', entropy: '3.1b', alertsVal: '1' },
  { dateLabel: '13 Jul', x: 200, blueY: 66, greenY: 142, orangeY: 164, yellowY: 189, qpm: '1,180/m', nx: '18', entropy: '3.5b', alertsVal: '3' },
  { dateLabel: '15 Jul', x: 260, blueY: 96, greenY: 118, orangeY: 166, yellowY: 193, qpm: '980/m', nx: '15', entropy: '3.3b', alertsVal: '2' },
  { dateLabel: '17 Jul', x: 320, blueY: 74, greenY: 148, orangeY: 163, yellowY: 188, qpm: '1,095/m', nx: '19', entropy: '3.6b', alertsVal: '4' },
  { dateLabel: '19 Jul', x: 380, blueY: 88, greenY: 126, orangeY: 170, yellowY: 187, qpm: '1,015/m', nx: '17', entropy: '3.4b', alertsVal: '2' },
  { dateLabel: '21 Jul', x: 440, blueY: 78, greenY: 138, orangeY: 165, yellowY: 188, qpm: '1,060/m', nx: '20', entropy: '3.7b', alertsVal: '3' },
  { dateLabel: 'May 2026', x: 500, blueY: 84, greenY: 120, orangeY: 167, yellowY: 186, qpm: '1,039h', nx: '21h', entropy: '40%', alertsVal: '$13,055.80' },
  { dateLabel: '23 Jul', x: 560, blueY: 102, greenY: 144, orangeY: 171, yellowY: 185, qpm: '940/m', nx: '22', entropy: '3.8b', alertsVal: '5' },
  { dateLabel: '25 Jul', x: 620, blueY: 124, greenY: 156, orangeY: 168, yellowY: 188, qpm: '860/m', nx: '18', entropy: '3.5b', alertsVal: '3' },
  { dateLabel: '27 Jul', x: 680, blueY: 94, greenY: 132, orangeY: 174, yellowY: 186, qpm: '1,010/m', nx: '15', entropy: '3.3b', alertsVal: '2' },
  { dateLabel: '29 Jul', x: 740, blueY: 106, greenY: 140, orangeY: 172, yellowY: 184, qpm: '970/m', nx: '14', entropy: '3.2b', alertsVal: '2' },
  { dateLabel: '31 Jul', x: 800, blueY: 98, greenY: 134, orangeY: 170, yellowY: 183, qpm: '1,005/m', nx: '16', entropy: '3.4b', alertsVal: '3' },
];

function buildSmoothPolyline(points: Array<{ x: number; y: number }>): string {
  return points.map((p) => `${p.x},${p.y}`).join(' ');
}

function OverviewChart({
  totalDnsQueries,
  nxdomainCount,
  entropyRate,
  alertScore,
}: OverviewChartProps) {
  const [activeIdx, setActiveIdx] = useState<number>(8);
  const currentPoint = CHART_POINTS[activeIdx] || CHART_POINTS[8];

  const bluePoints = buildSmoothPolyline(CHART_POINTS.map((p) => ({ x: p.x, y: p.blueY })));
  const greenPoints = buildSmoothPolyline(CHART_POINTS.map((p) => ({ x: p.x, y: p.greenY })));
  const orangePoints = buildSmoothPolyline(CHART_POINTS.map((p) => ({ x: p.x, y: p.orangeY })));
  const yellowPoints = buildSmoothPolyline(CHART_POINTS.map((p) => ({ x: p.x, y: p.yellowY })));

  return (
    <section className="dashboard-section" aria-label="Network & DNS Telemetry Overview">
      <div className="tm-card-header">
        <h2 className="tm-card-title">Overview</h2>

        <div className="tm-legend-list">
          <span className="tm-legend-item">
            <span className="tm-legend-dot" style={{ background: '#2563eb' }} />
            DNS Volume
          </span>
          <span className="tm-legend-item">
            <span className="tm-legend-dot" style={{ background: '#f59e0b' }} />
            NXDOMAIN
          </span>
          <span className="tm-legend-item">
            <span className="tm-legend-dot" style={{ background: '#ff6b00' }} />
            Entropy Ratio
          </span>
          <span className="tm-legend-item">
            <span className="tm-legend-dot" style={{ background: '#10b981' }} />
            IDS Threat Score
          </span>
        </div>
      </div>

      <div className="tm-chart-wrap">
        <svg
          className="tm-chart-svg"
          viewBox="0 0 820 230"
          preserveAspectRatio="none"
          role="img"
          aria-label="Multi-line telemetry time series chart"
        >
          <defs>
            <linearGradient id="tmBlueGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#2563eb" stopOpacity="0.12" />
              <stop offset="100%" stopColor="#2563eb" stopOpacity="0.0" />
            </linearGradient>
            <linearGradient id="tmGreenGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#10b981" stopOpacity="0.1" />
              <stop offset="100%" stopColor="#10b981" stopOpacity="0.0" />
            </linearGradient>
          </defs>

          {/* Subtle horizontal grid lines */}
          {[35, 75, 115, 155, 195].map((y) => (
            <line
              key={y}
              x1="15"
              y1={y}
              x2="805"
              y2={y}
              stroke="#f1f5f9"
              strokeWidth="1"
            />
          ))}

          {/* Area fills */}
          <polygon
            points={`20,195 ${bluePoints} 800,195`}
            fill="url(#tmBlueGrad)"
          />
          <polygon
            points={`20,195 ${greenPoints} 800,195`}
            fill="url(#tmGreenGrad)"
          />

          {/* 4 Telemetry Series Lines */}
          <polyline
            fill="none"
            stroke="#2563eb"
            strokeWidth="1.8"
            strokeLinejoin="round"
            strokeLinecap="round"
            points={bluePoints}
          />
          <polyline
            fill="none"
            stroke="#10b981"
            strokeWidth="1.8"
            strokeLinejoin="round"
            strokeLinecap="round"
            points={greenPoints}
          />
          <polyline
            fill="none"
            stroke="#ff6b00"
            strokeWidth="1.8"
            strokeLinejoin="round"
            strokeLinecap="round"
            points={orangePoints}
          />
          <polyline
            fill="none"
            stroke="#eab308"
            strokeWidth="1.8"
            strokeLinejoin="round"
            strokeLinecap="round"
            points={yellowPoints}
          />

          {/* Vertical dashed inspection line */}
          <line
            x1={currentPoint.x}
            y1="15"
            x2={currentPoint.x}
            y2="195"
            stroke="#94a3b8"
            strokeWidth="1.3"
            strokeDasharray="4 4"
          />

          {/* Active point marker */}
          <circle
            cx={currentPoint.x}
            cy={currentPoint.blueY}
            r="4.5"
            fill="#ffffff"
            stroke="#64748b"
            strokeWidth="2"
          />

          {/* Interactive hover columns */}
          {CHART_POINTS.map((pt, idx) => (
            <rect
              key={pt.dateLabel}
              x={pt.x - 25}
              y="10"
              width="50"
              height="190"
              fill="transparent"
              style={{ cursor: 'pointer' }}
              onMouseEnter={() => setActiveIdx(idx)}
            />
          ))}

          {/* X-axis labels */}
          {[
            { label: '7 Jul', x: 75 },
            { label: '11 Jul', x: 185 },
            { label: '15 Jul', x: 295 },
            { label: '19 Jul', x: 405 },
            { label: '23 Jul', x: 525 },
            { label: '27 Jul', x: 635 },
            { label: '31 Jul', x: 745 },
          ].map((tick) => (
            <text
              key={tick.label}
              x={tick.x}
              y="220"
              fill="#94a3b8"
              fontSize="11"
              textAnchor="middle"
            >
              {tick.label}
            </text>
          ))}
        </svg>

        {/* Floating Tooltip matching the screenshot */}
        <div
          className="tm-chart-tooltip"
          style={{
            left: `clamp(16px, calc(${(currentPoint.x / 820) * 100}% + 14px), calc(100% - 175px))`,
          }}
        >
          <div className="tm-tooltip-date">
            {activeIdx === 8 ? 'Live Telemetry' : currentPoint.dateLabel}
          </div>
          <div className="tm-tooltip-row">
            <span className="tm-kpi-dot-icon blue" style={{ width: 15, height: 15, fontSize: 9 }}>
              ●
            </span>
            <span>{activeIdx === 8 ? totalDnsQueries : currentPoint.qpm}</span>
          </div>
          <div className="tm-tooltip-row">
            <span className="tm-kpi-dot-icon yellow" style={{ width: 15, height: 15, fontSize: 9 }}>
              ●
            </span>
            <span>{activeIdx === 8 ? nxdomainCount : currentPoint.nx}</span>
          </div>
          <div className="tm-tooltip-row">
            <span className="tm-kpi-dot-icon orange" style={{ width: 15, height: 15, fontSize: 9 }}>
              ●
            </span>
            <span>{activeIdx === 8 ? entropyRate : currentPoint.entropy}</span>
          </div>
          <div className="tm-tooltip-row">
            <span className="tm-kpi-dot-icon green" style={{ width: 15, height: 15, fontSize: 9 }}>
              ●
            </span>
            <span>{activeIdx === 8 ? alertScore : currentPoint.alertsVal}</span>
          </div>
        </div>
      </div>
    </section>
  );
}

export default OverviewChart;

