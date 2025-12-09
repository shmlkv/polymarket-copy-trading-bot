'use client';

import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  Cell,
} from 'recharts';
import { TraderAnalysis } from '@/types/trader';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

interface PnLBarChartProps {
  traders: TraderAnalysis[];
}

export function PnLBarChart({ traders }: PnLBarChartProps) {
  const data = traders
    .map((t) => ({
      name: t.label.length > 15 ? t.label.slice(0, 12) + '...' : t.label,
      fullName: t.label,
      pnl: Number(t.pnl.total.toFixed(2)),
      roi: Number(t.pnl.roi.toFixed(2)),
    }))
    .sort((a, b) => b.pnl - a.pnl);

  return (
    <Card>
      <CardHeader>
        <CardTitle>P&L Comparison</CardTitle>
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
                name === 'pnl' ? `$${value.toFixed(2)}` : `${value.toFixed(2)}%`,
                name === 'pnl' ? 'P&L' : 'ROI',
              ]}
              labelFormatter={(label, payload) => {
                if (payload && payload[0]) {
                  return payload[0].payload.fullName;
                }
                return label;
              }}
            />
            <Legend />
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
