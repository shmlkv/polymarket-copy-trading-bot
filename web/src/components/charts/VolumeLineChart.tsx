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

interface VolumeLineChartProps {
  traders: TraderAnalysis[];
}

const COLORS = [
  '#3b82f6',
  '#22c55e',
  '#f97316',
  '#a855f7',
  '#ec4899',
  '#14b8a6',
  '#eab308',
  '#ef4444',
  '#6366f1',
  '#84cc16',
];

export function VolumeLineChart({ traders }: VolumeLineChartProps) {
  // Aggregate all months from all traders
  const allMonths = new Set<string>();
  traders.forEach((t) => {
    t.monthlyBreakdown?.forEach((m) => allMonths.add(m.month));
  });

  const sortedMonths = Array.from(allMonths).sort();

  // Build data for chart - total volume (bought + sold)
  const data = sortedMonths.map((month) => {
    const point: Record<string, string | number> = { month };

    traders.forEach((t) => {
      const monthData = t.monthlyBreakdown?.find((m) => m.month === month);
      const shortLabel = t.label.length > 10 ? t.label.slice(0, 10) : t.label;
      point[shortLabel] = monthData
        ? Number((monthData.totalBought + monthData.totalSold).toFixed(2))
        : 0;
    });

    return point;
  });

  if (data.length === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Monthly Trading Volume</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-muted-foreground">No monthly data available</p>
        </CardContent>
      </Card>
    );
  }

  const traderLabels = traders.map((t) =>
    t.label.length > 10 ? t.label.slice(0, 10) : t.label
  );

  return (
    <Card>
      <CardHeader>
        <CardTitle>Monthly Trading Volume</CardTitle>
      </CardHeader>
      <CardContent>
        <ResponsiveContainer width="100%" height={400}>
          <LineChart data={data} margin={{ top: 20, right: 30, left: 20, bottom: 20 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#333" />
            <XAxis dataKey="month" tick={{ fill: '#888' }} />
            <YAxis
              tick={{ fill: '#888' }}
              tickFormatter={(value) => `$${value}`}
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
            <Legend />
            {traderLabels.map((label, index) => (
              <Line
                key={label}
                type="monotone"
                dataKey={label}
                stroke={COLORS[index % COLORS.length]}
                strokeWidth={2}
                dot={{ fill: COLORS[index % COLORS.length], r: 4 }}
                activeDot={{ r: 6 }}
              />
            ))}
          </LineChart>
        </ResponsiveContainer>
      </CardContent>
    </Card>
  );
}
