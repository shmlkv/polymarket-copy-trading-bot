'use client';

import { LineChart, Line, ResponsiveContainer } from 'recharts';
import { TraderAnalysis } from '@/types/trader';
import { TimeRange, filterByTimeRange } from '@/components/TimeRangeFilter';

interface VolumeSparklineProps {
  traders: TraderAnalysis[];
  timeRange?: TimeRange;
}

export function VolumeSparkline({ traders, timeRange = 'all' }: VolumeSparklineProps) {
  // Filter monthly data by time range
  const filteredTraders = traders.map((t) => ({
    ...t,
    monthlyBreakdown: t.monthlyBreakdown ? filterByTimeRange(t.monthlyBreakdown, timeRange, 'month') : [],
  }));

  // Aggregate volume by month across all traders
  const volumeByMonth: Record<string, number> = {};

  filteredTraders.forEach((trader) => {
    if (trader.monthlyBreakdown) {
      trader.monthlyBreakdown.forEach((mp) => {
        const key = mp.month;
        volumeByMonth[key] = (volumeByMonth[key] || 0) + mp.totalBought + mp.totalSold;
      });
    }
  });

  const data = Object.entries(volumeByMonth)
    .sort(([a], [b]) => a.localeCompare(b))
    .slice(-6) // Last 6 months
    .map(([month, volume]) => ({ month, volume }));

  // Calculate total volume based on filtered data
  const totalVolume = filteredTraders.reduce(
    (sum, t) => sum + (t.monthlyBreakdown?.reduce((s, m) => s + m.totalBought + m.totalSold, 0) || 0),
    0
  );

  // Determine trend
  const trend = data.length >= 2
    ? data[data.length - 1].volume > data[0].volume
      ? 'up'
      : 'down'
    : 'flat';

  return (
    <div className="bg-card rounded-xl border p-3 flex flex-col h-full">
      <span className="text-xs text-muted-foreground mb-1">Volume</span>
      <div className="flex items-center gap-2 mb-1">
        <span className="text-lg font-bold font-mono">
          ${totalVolume >= 1000000
            ? (totalVolume / 1000000).toFixed(1) + 'M'
            : totalVolume >= 1000
              ? (totalVolume / 1000).toFixed(0) + 'K'
              : totalVolume.toFixed(0)
          }
        </span>
        <span className={`text-xs ${trend === 'up' ? 'text-green-500' : trend === 'down' ? 'text-red-500' : 'text-muted-foreground'}`}>
          {trend === 'up' ? '↑' : trend === 'down' ? '↓' : '→'}
        </span>
      </div>
      <div className="flex-1 min-h-[30px]">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={data}>
            <Line
              type="monotone"
              dataKey="volume"
              stroke={trend === 'up' ? '#22c55e' : trend === 'down' ? '#ef4444' : '#71717a'}
              strokeWidth={2}
              dot={false}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
