'use client';

import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from 'recharts';
import { TraderAnalysis } from '@/types/trader';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { TimeRange, filterByTimeRange } from '@/components/TimeRangeFilter';

interface MonthlyLineChartProps {
  traders: TraderAnalysis[];
  compact?: boolean;
  timeRange?: TimeRange;
}

const COLORS = [
  '#3b82f6', // blue
  '#22c55e', // green
  '#f97316', // orange
  '#a855f7', // purple
  '#ec4899', // pink
  '#14b8a6', // teal
  '#eab308', // yellow
  '#ef4444', // red
  '#6366f1', // indigo
  '#84cc16', // lime
];

export function MonthlyLineChart({ traders, compact = false, timeRange = 'all' }: MonthlyLineChartProps) {
  // Filter monthly data by time range
  const filteredTraders = traders.map((t) => ({
    ...t,
    monthlyBreakdown: t.monthlyBreakdown ? filterByTimeRange(t.monthlyBreakdown, timeRange, 'month') : [],
  }));

  // Aggregate all months from all traders
  const allMonths = new Set<string>();
  filteredTraders.forEach((t) => {
    t.monthlyBreakdown?.forEach((m) => allMonths.add(m.month));
  });

  const sortedMonths = Array.from(allMonths).sort();

  // Build data for chart - show realizedPnl
  const data = sortedMonths.map((month) => {
    const point: Record<string, string | number> = { month };

    filteredTraders.forEach((t) => {
      const monthData = t.monthlyBreakdown?.find((m) => m.month === month);
      const shortLabel = t.label.length > 8 ? t.label.slice(0, 6) + '..' : t.label;
      point[shortLabel] = monthData ? Number((monthData.realizedPnl || 0).toFixed(2)) : 0;
    });

    return point;
  });

  if (data.length === 0) {
    return (
      <Card className={compact ? 'h-full' : ''}>
        <CardHeader className={compact ? 'pb-2 pt-3 px-4' : ''}>
          <CardTitle className={compact ? 'text-sm' : ''}>Monthly P&L</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-muted-foreground text-sm">No monthly data available</p>
        </CardContent>
      </Card>
    );
  }

  const traderLabels = traders.map((t) =>
    t.label.length > 8 ? t.label.slice(0, 6) + '..' : t.label
  );

  return (
    <Card className={compact ? 'h-full' : ''}>
      <CardHeader className={compact ? 'pb-2 pt-3 px-4' : ''}>
        <CardTitle className={compact ? 'text-sm' : ''}>Monthly P&L</CardTitle>
      </CardHeader>
      <CardContent className={compact ? 'pb-3 px-2' : ''}>
        <ResponsiveContainer width="100%" height={compact ? 180 : 250}>
          <LineChart
            data={data}
            margin={compact ? { top: 5, right: 10, left: 0, bottom: 5 } : { top: 10, right: 20, left: 10, bottom: 10 }}
          >
            <CartesianGrid strokeDasharray="3 3" stroke="#333" vertical={false} />
            <XAxis
              dataKey="month"
              tick={{ fill: '#888', fontSize: compact ? 10 : 12 }}
              axisLine={{ stroke: '#333' }}
            />
            <YAxis
              tick={{ fill: '#888', fontSize: compact ? 10 : 12 }}
              tickFormatter={(value) => `$${value >= 1000 ? (value / 1000).toFixed(0) + 'k' : value}`}
              width={compact ? 40 : 60}
              axisLine={{ stroke: '#333' }}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: '#1a1a1a',
                border: '1px solid #333',
                borderRadius: '8px',
                color: '#fff',
              }}
              labelStyle={{ color: '#fff' }}
              itemStyle={{ color: '#fff' }}
              formatter={(value: number) => [`$${value.toFixed(2)}`, '']}
            />
            {!compact && <Legend />}
            {traderLabels.map((label, index) => (
              <Line
                key={label}
                type="monotone"
                dataKey={label}
                stroke={COLORS[index % COLORS.length]}
                strokeWidth={compact ? 1.5 : 2}
                dot={compact ? false : { fill: COLORS[index % COLORS.length], r: 4 }}
                activeDot={{ r: compact ? 4 : 6 }}
              />
            ))}
          </LineChart>
        </ResponsiveContainer>
      </CardContent>
    </Card>
  );
}
