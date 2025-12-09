'use client';

import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from 'recharts';
import { TraderCopyStats } from '@/types/myTrades';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

interface TradesPieChartProps {
  byTrader: TraderCopyStats[];
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

export function TradesPieChart({ byTrader }: TradesPieChartProps) {
  const data = byTrader
    .filter((t) => t.tradeCount > 0)
    .map((t, index) => ({
      name: t.traderLabel,
      value: t.tradeCount,
      fill: COLORS[index % COLORS.length],
    }))
    .sort((a, b) => b.value - a.value);

  if (data.length === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Trades Distribution by Trader</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-muted-foreground">No trade data available</p>
        </CardContent>
      </Card>
    );
  }

  const total = data.reduce((sum, d) => sum + d.value, 0);

  return (
    <Card>
      <CardHeader>
        <CardTitle>Trades Distribution by Trader</CardTitle>
      </CardHeader>
      <CardContent>
        <ResponsiveContainer width="100%" height={400}>
          <PieChart>
            <Pie
              data={data}
              cx="50%"
              cy="50%"
              innerRadius={60}
              outerRadius={120}
              paddingAngle={2}
              dataKey="value"
              label={({ name, percent }: { name?: string; percent?: number }) => {
                const label = name ?? '';
                const pct = percent ?? 0;
                return `${label.length > 10 ? label.slice(0, 8) + '...' : label} (${(pct * 100).toFixed(0)}%)`;
              }}
              labelLine={{ stroke: '#666' }}
            >
              {data.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.fill} />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{
                backgroundColor: '#1a1a1a',
                border: '1px solid #333',
                borderRadius: '8px',
                color: '#fff',
              }}
              labelStyle={{ color: '#fff' }}
              itemStyle={{ color: '#fff' }}
              formatter={(value: number, name: string) => [
                `${value} trades (${((value / total) * 100).toFixed(1)}%)`,
                name,
              ]}
            />
            <Legend
              formatter={(value) => (
                <span style={{ color: '#888' }}>
                  {value.length > 15 ? value.slice(0, 12) + '...' : value}
                </span>
              )}
            />
          </PieChart>
        </ResponsiveContainer>
      </CardContent>
    </Card>
  );
}
