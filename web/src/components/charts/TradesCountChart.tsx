'use client';

import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from 'recharts';
import { TraderCopyStats } from '@/types/myTrades';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

interface TradesCountChartProps {
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
];

export function TradesCountChart({ byTrader }: TradesCountChartProps) {
  const data = byTrader
    .filter(t => t.tradeCount > 0)
    .map((t) => ({
      name: t.traderLabel.length > 12 ? t.traderLabel.slice(0, 10) + '...' : t.traderLabel,
      fullName: t.traderLabel,
      trades: t.tradeCount,
      volume: Number(t.totalBought.toFixed(2)),
    }))
    .sort((a, b) => b.trades - a.trades);

  return (
    <Card>
      <CardHeader>
        <CardTitle>Trades Count by Copied Trader</CardTitle>
      </CardHeader>
      <CardContent>
        <ResponsiveContainer width="100%" height={400}>
          <BarChart data={data} margin={{ top: 20, right: 30, left: 20, bottom: 60 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#333" />
            <XAxis
              dataKey="name"
              angle={-45}
              textAnchor="end"
              height={80}
              tick={{ fill: '#888', fontSize: 12 }}
            />
            <YAxis tick={{ fill: '#888' }} />
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
                name === 'trades' ? value : `$${value.toFixed(2)}`,
                name === 'trades' ? 'Trades' : 'Volume',
              ]}
              labelFormatter={(label, payload) => {
                if (payload && payload[0]) {
                  return payload[0].payload.fullName;
                }
                return label;
              }}
            />
            <Bar dataKey="trades" name="Trades" radius={[4, 4, 0, 0]}>
              {data.map((entry, index) => (
                <Cell
                  key={`cell-${index}`}
                  fill={COLORS[index % COLORS.length]}
                />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </CardContent>
    </Card>
  );
}
