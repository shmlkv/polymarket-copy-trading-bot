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
import { TraderAnalysis } from '@/types/trader';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { TimeRange, filterByTimeRange } from '@/components/TimeRangeFilter';

interface PnLBarChartProps {
  traders: TraderAnalysis[];
  compact?: boolean;
  timeRange?: TimeRange;
}

export function PnLBarChart({ traders, compact = false, timeRange = 'all' }: PnLBarChartProps) {
  // Calculate P&L from daily realizedPnl filtered by time range
  const data = traders
    .map((t) => {
      const filteredDaily = t.dailyBreakdown ? filterByTimeRange(t.dailyBreakdown, timeRange, 'date') : [];
      const pnl = timeRange === 'all'
        ? t.pnl.total
        : filteredDaily.reduce((sum, d) => sum + (d.realizedPnl || 0), 0);
      const volume = timeRange === 'all'
        ? t.volume.totalBought
        : filteredDaily.reduce((sum, d) => sum + d.totalBought, 0);
      return {
        name: t.label.length > 8 ? t.label.slice(0, 6) + '..' : t.label,
        fullName: t.label,
        pnl: Number(pnl.toFixed(2)),
        volume,
      };
    })
    .sort((a, b) => b.pnl - a.pnl);

  const totalPnL = data.reduce((sum, d) => sum + d.pnl, 0);

  return (
    <Card className={compact ? 'h-full' : ''}>
      <CardHeader className={compact ? 'pb-2 pt-3 px-4' : ''}>
        <div className="flex items-center justify-between">
          <CardTitle className={compact ? 'text-sm' : ''}>P&L</CardTitle>
          <span
            className={`font-mono font-bold ${totalPnL >= 0 ? 'text-green-500' : 'text-red-500'} ${compact ? 'text-lg' : 'text-xl'}`}
          >
            {totalPnL >= 0 ? '+' : ''}${totalPnL.toLocaleString('en-US', { maximumFractionDigits: 0 })}
          </span>
        </div>
      </CardHeader>
      <CardContent className={compact ? 'pb-3 px-2' : ''}>
        <ResponsiveContainer width="100%" height={compact ? 240 : 250}>
          <BarChart
            data={data}
            margin={compact ? { top: 5, right: 5, left: 0, bottom: 40 } : { top: 10, right: 20, left: 10, bottom: 50 }}
          >
            <CartesianGrid strokeDasharray="3 3" stroke="#333" vertical={false} />
            <XAxis
              dataKey="name"
              angle={-45}
              textAnchor="end"
              height={compact ? 50 : 80}
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
