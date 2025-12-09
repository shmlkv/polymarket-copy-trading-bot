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

interface DailyLineChartProps {
  traders: TraderAnalysis[];
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

export function DailyLineChart({ traders }: DailyLineChartProps) {
  // Aggregate all dates from all traders
  const allDates = new Set<string>();
  traders.forEach((t) => {
    t.dailyBreakdown?.forEach((d) => allDates.add(d.date));
  });

  const sortedDates = Array.from(allDates).sort();

  // Build data for chart
  const data = sortedDates.map((date) => {
    const point: Record<string, string | number> = { date: date.slice(5) }; // MM-DD format
    point.fullDate = date;

    traders.forEach((t) => {
      const dayData = t.dailyBreakdown?.find((d) => d.date === date);
      const shortLabel = t.label.length > 10 ? t.label.slice(0, 10) : t.label;
      point[shortLabel] = dayData ? Number(dayData.netFlow.toFixed(2)) : 0;
    });

    return point;
  });

  if (data.length === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Daily Net Flow</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-muted-foreground">No daily data available</p>
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
        <CardTitle>Daily Net Flow (Sold - Bought)</CardTitle>
      </CardHeader>
      <CardContent>
        <ResponsiveContainer width="100%" height={400}>
          <LineChart data={data} margin={{ top: 20, right: 30, left: 20, bottom: 20 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#333" />
            <XAxis dataKey="date" tick={{ fill: '#888' }} />
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
              labelFormatter={(label, payload) => {
                if (payload && payload[0]) {
                  return payload[0].payload.fullDate;
                }
                return label;
              }}
            />
            <Legend />
            {traderLabels.map((label, index) => (
              <Line
                key={label}
                type="monotone"
                dataKey={label}
                stroke={COLORS[index % COLORS.length]}
                strokeWidth={2}
                dot={{ fill: COLORS[index % COLORS.length], r: 3 }}
                activeDot={{ r: 5 }}
              />
            ))}
          </LineChart>
        </ResponsiveContainer>
      </CardContent>
    </Card>
  );
}
