'use client';

import { TraderAnalysis } from '@/types/trader';
import { TimeRange } from '@/components/TimeRangeFilter';

interface WinRateGaugeProps {
  traders: TraderAnalysis[];
  timeRange?: TimeRange;
}

export function WinRateGauge({ traders, timeRange = 'all' }: WinRateGaugeProps) {
  // Win rate is based on positions, not time-filtered (positions don't have dates)
  // So we show overall win rate regardless of time range
  const avgWinRate =
    traders.length > 0
      ? traders.reduce((sum, t) => sum + t.positions.winRate, 0) / traders.length
      : 0;

  // SVG gauge parameters
  const size = 120;
  const strokeWidth = 12;
  const radius = (size - strokeWidth) / 2;
  const circumference = Math.PI * radius; // half circle
  const progress = (avgWinRate / 100) * circumference;

  // Color based on win rate
  const getColor = (rate: number) => {
    if (rate >= 60) return '#22c55e';
    if (rate >= 45) return '#eab308';
    return '#ef4444';
  };

  return (
    <div className="bg-card rounded-xl border p-3 flex flex-col items-center justify-center h-full">
      <span className="text-xs text-muted-foreground mb-1">Win Rate</span>
      <div className="relative" style={{ width: size, height: size / 2 + 10 }}>
        <svg
          width={size}
          height={size / 2 + 10}
          viewBox={`0 0 ${size} ${size / 2 + 10}`}
        >
          {/* Background arc */}
          <path
            d={`M ${strokeWidth / 2} ${size / 2} A ${radius} ${radius} 0 0 1 ${size - strokeWidth / 2} ${size / 2}`}
            fill="none"
            stroke="#262626"
            strokeWidth={strokeWidth}
            strokeLinecap="round"
          />
          {/* Progress arc */}
          <path
            d={`M ${strokeWidth / 2} ${size / 2} A ${radius} ${radius} 0 0 1 ${size - strokeWidth / 2} ${size / 2}`}
            fill="none"
            stroke={getColor(avgWinRate)}
            strokeWidth={strokeWidth}
            strokeLinecap="round"
            strokeDasharray={`${progress} ${circumference}`}
            style={{ transition: 'stroke-dasharray 0.5s ease' }}
          />
        </svg>
        {/* Center text */}
        <div className="absolute inset-0 flex items-end justify-center pb-1">
          <span
            className="text-2xl font-bold font-mono"
            style={{ color: getColor(avgWinRate) }}
          >
            {avgWinRate.toFixed(1)}%
          </span>
        </div>
      </div>
    </div>
  );
}
