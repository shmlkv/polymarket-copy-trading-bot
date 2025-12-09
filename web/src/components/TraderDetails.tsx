'use client';

import { TraderAnalysis } from '@/types/trader';

interface TraderDetailsProps {
  trader: TraderAnalysis;
}

export function TraderDetails({ trader }: TraderDetailsProps) {
  const formatCurrency = (value: number) => {
    const formatted = Math.abs(value).toFixed(2);
    return value >= 0 ? `$${formatted}` : `-$${formatted}`;
  };

  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
      {/* Stats Summary */}
      <div className="space-y-3">
        <h4 className="font-semibold text-sm text-muted-foreground uppercase tracking-wide">
          Statistics
        </h4>
        <div className="grid grid-cols-2 gap-2 text-sm">
          <div>
            <span className="text-muted-foreground">Unrealized P&L:</span>
          </div>
          <div
            className={`font-mono text-right ${
              trader.pnl.unrealized >= 0 ? 'text-green-500' : 'text-red-500'
            }`}
          >
            {formatCurrency(trader.pnl.unrealized)}
          </div>

          <div>
            <span className="text-muted-foreground">Realized P&L:</span>
          </div>
          <div
            className={`font-mono text-right ${
              trader.pnl.realized >= 0 ? 'text-green-500' : 'text-red-500'
            }`}
          >
            {formatCurrency(trader.pnl.realized)}
          </div>

          <div>
            <span className="text-muted-foreground">Monthly ROI:</span>
          </div>
          <div className="font-mono text-right">{trader.pnl.monthlyRoi.toFixed(2)}%</div>

          <div>
            <span className="text-muted-foreground">Open Positions:</span>
          </div>
          <div className="font-mono text-right">{trader.positions.open}</div>

          <div>
            <span className="text-muted-foreground">Days Active:</span>
          </div>
          <div className="font-mono text-right">{trader.trades.daysActive}</div>

          {trader.redeemable.count > 0 && (
            <>
              <div>
                <span className="text-muted-foreground">Redeemable:</span>
              </div>
              <div className="font-mono text-right text-yellow-500">
                {trader.redeemable.count} ({formatCurrency(trader.redeemable.value)})
              </div>
            </>
          )}
        </div>

        <a
          href={`https://polymarket.com/profile/${trader.address}`}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-block text-sm text-blue-400 hover:text-blue-300 mt-2"
        >
          View on Polymarket →
        </a>
      </div>

      {/* Top Winners */}
      <div className="space-y-3">
        <h4 className="font-semibold text-sm text-muted-foreground uppercase tracking-wide">
          Top Winners
        </h4>
        {trader.topWinners.length > 0 ? (
          <ul className="space-y-2">
            {trader.topWinners.map((pos, idx) => (
              <li key={idx} className="text-sm">
                <div className="flex justify-between items-start gap-2">
                  <span className="text-green-500 font-mono shrink-0">
                    +${pos.pnl.toFixed(2)}
                  </span>
                  <span className="text-right text-muted-foreground truncate">
                    {pos.title.length > 40 ? pos.title.slice(0, 37) + '...' : pos.title}
                  </span>
                </div>
                <div className="text-xs text-muted-foreground text-right">
                  {pos.outcome}
                </div>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-sm text-muted-foreground">No winning positions</p>
        )}
      </div>

      {/* Top Losers */}
      <div className="space-y-3">
        <h4 className="font-semibold text-sm text-muted-foreground uppercase tracking-wide">
          Top Losers
        </h4>
        {trader.topLosers.length > 0 ? (
          <ul className="space-y-2">
            {trader.topLosers.map((pos, idx) => (
              <li key={idx} className="text-sm">
                <div className="flex justify-between items-start gap-2">
                  <span className="text-red-500 font-mono shrink-0">
                    -${Math.abs(pos.pnl).toFixed(2)}
                  </span>
                  <span className="text-right text-muted-foreground truncate">
                    {pos.title.length > 40 ? pos.title.slice(0, 37) + '...' : pos.title}
                  </span>
                </div>
                <div className="text-xs text-muted-foreground text-right">
                  {pos.outcome}
                </div>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-sm text-muted-foreground">No losing positions</p>
        )}
      </div>
    </div>
  );
}
