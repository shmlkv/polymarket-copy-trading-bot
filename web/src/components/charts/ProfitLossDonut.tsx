'use client';

import { PieChart, Pie, Cell, ResponsiveContainer } from 'recharts';
import { TraderAnalysis } from '@/types/trader';
import { TimeRange, filterByTimeRange } from '@/components/TimeRangeFilter';

interface ProfitLossDonutProps {
  traders: TraderAnalysis[];
  timeRange?: TimeRange;
}

export function ProfitLossDonut({ traders, timeRange = 'all' }: ProfitLossDonutProps) {
  // Calculate P&L for each trader based on time range
  const traderPnLs = traders.map((t) => {
    if (timeRange === 'all') return t.pnl.total;
    const filteredDaily = t.dailyBreakdown ? filterByTimeRange(t.dailyBreakdown, timeRange, 'date') : [];
    return filteredDaily.reduce((sum, d) => sum + (d.realizedPnl || 0), 0);
  });

  const profitable = traderPnLs.filter((pnl) => pnl > 0).length;
  const losing = traderPnLs.filter((pnl) => pnl < 0).length;
  const breakeven = traders.length - profitable - losing;

  const data = [
    { name: 'Profitable', value: profitable, color: '#22c55e' },
    { name: 'Losing', value: losing, color: '#ef4444' },
    ...(breakeven > 0 ? [{ name: 'Breakeven', value: breakeven, color: '#71717a' }] : []),
  ].filter((d) => d.value > 0);

  const total = traders.length;

  return (
    <div className="bg-card rounded-xl border p-3 flex flex-col items-center justify-center h-full">
      <span className="text-xs text-muted-foreground mb-1">Traders P/L</span>
      <div className="relative" style={{ width: 100, height: 80 }}>
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={data}
              cx="50%"
              cy="50%"
              innerRadius={25}
              outerRadius={38}
              paddingAngle={2}
              dataKey="value"
              startAngle={180}
              endAngle={-180}
            >
              {data.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.color} stroke="none" />
              ))}
            </Pie>
          </PieChart>
        </ResponsiveContainer>
        {/* Center text */}
        <div className="absolute inset-0 flex items-center justify-center">
          <div className="text-center">
            <span className="text-lg font-bold font-mono text-green-500">{profitable}</span>
            <span className="text-muted-foreground text-xs">/</span>
            <span className="text-lg font-bold font-mono text-red-500">{losing}</span>
          </div>
        </div>
      </div>
      <div className="flex gap-2 text-[10px] text-muted-foreground mt-1">
        <span className="flex items-center gap-1">
          <span className="w-2 h-2 rounded-full bg-green-500"></span>Win
        </span>
        <span className="flex items-center gap-1">
          <span className="w-2 h-2 rounded-full bg-red-500"></span>Loss
        </span>
      </div>
    </div>
  );
}
