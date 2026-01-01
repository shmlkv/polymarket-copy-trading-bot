'use client';

import { PieChart, Pie, Cell, ResponsiveContainer } from 'recharts';
import { TraderAnalysis } from '@/types/trader';
import { TimeRange } from '@/components/TimeRangeFilter';

interface ActivePositionsPieProps {
  traders: TraderAnalysis[];
  timeRange?: TimeRange;
}

export function ActivePositionsPie({ traders }: ActivePositionsPieProps) {
  // Aggregate open positions across all traders
  const totalOpen = traders.reduce((sum, t) => sum + t.positions.open, 0);
  const totalWins = traders.reduce((sum, t) => sum + t.positions.winners, 0);
  const totalLosses = traders.reduce((sum, t) => sum + t.positions.losers, 0);

  // For the pie, show wins vs losses ratio
  const data = [
    { name: 'Wins', value: totalWins, color: '#22c55e' },
    { name: 'Losses', value: totalLosses, color: '#ef4444' },
  ].filter((d) => d.value > 0);

  const total = totalWins + totalLosses;

  return (
    <div className="bg-card rounded-xl border p-4 flex flex-col items-center justify-center h-full">
      <span className="text-sm text-muted-foreground mb-2">Positions</span>
      <div className="flex items-center gap-4">
        {/* Mini pie */}
        <div className="relative" style={{ width: 70, height: 70 }}>
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={data}
                cx="50%"
                cy="50%"
                innerRadius={20}
                outerRadius={32}
                paddingAngle={2}
                dataKey="value"
              >
                {data.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} stroke="none" />
                ))}
              </Pie>
            </PieChart>
          </ResponsiveContainer>
          {/* Center number */}
          <div className="absolute inset-0 flex items-center justify-center">
            <span className="text-sm font-bold font-mono">{total}</span>
          </div>
        </div>

        {/* Stats */}
        <div className="flex flex-col gap-1">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-green-500"></span>
            <span className="text-xs text-muted-foreground">Wins</span>
            <span className="text-sm font-bold font-mono text-green-500">{totalWins}</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-red-500"></span>
            <span className="text-xs text-muted-foreground">Losses</span>
            <span className="text-sm font-bold font-mono text-red-500">{totalLosses}</span>
          </div>
          <div className="flex items-center gap-2 pt-1 border-t border-border">
            <span className="text-xs text-muted-foreground">Open</span>
            <span className="text-sm font-bold font-mono text-blue-500">{totalOpen}</span>
          </div>
        </div>
      </div>
    </div>
  );
}
