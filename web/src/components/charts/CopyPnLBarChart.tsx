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

interface CopyPnLBarChartProps {
  byTrader: TraderCopyStats[];
}

export function CopyPnLBarChart({ byTrader }: CopyPnLBarChartProps) {
  const data = byTrader
    .filter(t => t.tradeCount > 0)
    .map((t) => ({
      name: t.traderLabel.length > 12 ? t.traderLabel.slice(0, 10) + '...' : t.traderLabel,
      fullName: t.traderLabel,
      pnl: Number(t.pnl.toFixed(2)),
      trades: t.tradeCount,
    }))
    .sort((a, b) => b.pnl - a.pnl);

  return (
    <Card>
      <CardHeader>
        <CardTitle>P&L by Copied Trader</CardTitle>
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
              formatter={(value: number, name: string) => [
                name === 'pnl' ? `$${value.toFixed(2)}` : value,
                name === 'pnl' ? 'P&L' : 'Trades',
              ]}
              labelFormatter={(label, payload) => {
                if (payload && payload[0]) {
                  return payload[0].payload.fullName;
                }
                return label;
              }}
            />
            <Bar dataKey="pnl" name="P&L ($)" radius={[4, 4, 0, 0]}>
              {data.map((entry, index) => (
                <Cell
                  key={`cell-${index}`}
                  fill={entry.pnl >= 0 ? '#22c55e' : '#ef4444'}
                />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </CardContent>
    </Card>
  );
}
