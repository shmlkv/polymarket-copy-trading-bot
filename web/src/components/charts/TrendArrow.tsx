'use client';

import { TraderAnalysis } from '@/types/trader';
import { TimeRange, filterByTimeRange } from '@/components/TimeRangeFilter';

interface TrendArrowProps {
  traders: TraderAnalysis[];
  timeRange?: TimeRange;
}

export function TrendArrow({ traders, timeRange = '30d' }: TrendArrowProps) {
  // Calculate P&L for the selected time range using realizedPnl
  const totalPnL = timeRange === 'all'
    ? traders.reduce((sum, t) => sum + t.pnl.total, 0)
    : traders.reduce((sum, t) => {
        const filteredDaily = t.dailyBreakdown ? filterByTimeRange(t.dailyBreakdown, timeRange, 'date') : [];
        return sum + filteredDaily.reduce((s, d) => s + (d.realizedPnl || 0), 0);
      }, 0);
  const direction = totalPnL > 0 ? 'up' : totalPnL < 0 ? 'down' : 'flat';

  const getArrowColor = () => {
    if (direction === 'up') return 'text-green-500';
    if (direction === 'down') return 'text-red-500';
    return 'text-muted-foreground';
  };

  const getArrowIcon = () => {
    if (direction === 'up') return '↑';
    if (direction === 'down') return '↓';
    return '→';
  };

  const getTimeLabel = () => {
    switch (timeRange) {
      case '7d': return '7 days';
      case '30d': return '30 days';
      case '90d': return '90 days';
      default: return 'All time';
    }
  };

  return (
    <div className="bg-card rounded-xl border p-3 flex flex-col h-full">
      <span className="text-xs text-muted-foreground mb-1">Realized P&L</span>
      <div className="flex-1 flex items-center justify-center">
        <div className="text-center">
          <span className={`text-4xl font-bold ${getArrowColor()}`}>
            {getArrowIcon()}
          </span>
          <div className={`text-lg font-bold font-mono ${getArrowColor()}`}>
            {totalPnL >= 0 ? '+' : ''}${Math.abs(totalPnL).toLocaleString('en-US', { maximumFractionDigits: 0 })}
          </div>
          <div className="text-[10px] text-muted-foreground">
            {getTimeLabel()}
          </div>
        </div>
      </div>
    </div>
  );
}
