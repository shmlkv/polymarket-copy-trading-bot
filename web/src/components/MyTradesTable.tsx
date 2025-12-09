'use client';

import { useState } from 'react';
import { TraderCopyStats, CopyTrade } from '@/types/myTrades';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';

interface MyTradesTableProps {
  byTrader: TraderCopyStats[];
}

type SortKey = 'traderLabel' | 'pnl' | 'roi' | 'tradeCount' | 'totalBought';
type SortDir = 'asc' | 'desc';

export function MyTradesTable({ byTrader }: MyTradesTableProps) {
  const [sortKey, setSortKey] = useState<SortKey>('tradeCount');
  const [sortDir, setSortDir] = useState<SortDir>('desc');
  const [expandedTrader, setExpandedTrader] = useState<string | null>(null);

  const handleSort = (key: SortKey) => {
    if (sortKey === key) {
      setSortDir(sortDir === 'asc' ? 'desc' : 'asc');
    } else {
      setSortKey(key);
      setSortDir('desc');
    }
  };

  const sortedTraders = [...byTrader].sort((a, b) => {
    let aVal: number | string;
    let bVal: number | string;

    switch (sortKey) {
      case 'traderLabel':
        aVal = a.traderLabel.toLowerCase();
        bVal = b.traderLabel.toLowerCase();
        break;
      case 'pnl':
        aVal = a.pnl;
        bVal = b.pnl;
        break;
      case 'roi':
        aVal = a.roi;
        bVal = b.roi;
        break;
      case 'tradeCount':
        aVal = a.tradeCount;
        bVal = b.tradeCount;
        break;
      case 'totalBought':
        aVal = a.totalBought;
        bVal = b.totalBought;
        break;
      default:
        return 0;
    }

    if (typeof aVal === 'string' && typeof bVal === 'string') {
      return sortDir === 'asc' ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
    }

    return sortDir === 'asc' ? (aVal as number) - (bVal as number) : (bVal as number) - (aVal as number);
  });

  const SortButton = ({ label, sortKeyName }: { label: string; sortKeyName: SortKey }) => (
    <Button
      variant="ghost"
      size="sm"
      onClick={() => handleSort(sortKeyName)}
      className="h-auto p-0 hover:bg-transparent font-semibold"
    >
      {label}
      {sortKey === sortKeyName && (
        <span className="ml-1">{sortDir === 'asc' ? '↑' : '↓'}</span>
      )}
    </Button>
  );

  const formatCurrency = (value: number) => {
    const formatted = Math.abs(value).toFixed(2);
    return value >= 0 ? `$${formatted}` : `-$${formatted}`;
  };

  const formatTime = (timestamp: number) => {
    return new Date(timestamp * 1000).toLocaleString();
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>My Copy Trades by Trader</CardTitle>
      </CardHeader>
      <CardContent>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>
                <SortButton label="Trader" sortKeyName="traderLabel" />
              </TableHead>
              <TableHead className="text-right">
                <SortButton label="Trades" sortKeyName="tradeCount" />
              </TableHead>
              <TableHead className="text-right">
                <SortButton label="Bought" sortKeyName="totalBought" />
              </TableHead>
              <TableHead className="text-right">
                Sold
              </TableHead>
              <TableHead className="text-right">
                <SortButton label="Cash Flow" sortKeyName="pnl" />
              </TableHead>
              <TableHead className="text-right">
                <SortButton label="ROI %" sortKeyName="roi" />
              </TableHead>
              <TableHead className="text-right">
                Avg Trade
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {sortedTraders.map((trader) => (
              <>
                <TableRow
                  key={trader.traderAddress}
                  className="cursor-pointer hover:bg-muted/50"
                  onClick={() =>
                    setExpandedTrader(
                      expandedTrader === trader.traderAddress ? null : trader.traderAddress
                    )
                  }
                >
                  <TableCell className="font-medium">
                    <div className="flex items-center gap-2">
                      <span>{expandedTrader === trader.traderAddress ? '▼' : '▶'}</span>
                      <div>
                        <div>{trader.traderLabel}</div>
                        {trader.traderAddress !== 'unmatched' && (
                          <div className="text-xs text-muted-foreground">
                            {trader.traderAddress.slice(0, 8)}...
                          </div>
                        )}
                      </div>
                    </div>
                  </TableCell>
                  <TableCell className="text-right font-mono">
                    {trader.tradeCount}
                  </TableCell>
                  <TableCell className="text-right font-mono">
                    {formatCurrency(trader.totalBought)}
                  </TableCell>
                  <TableCell className="text-right font-mono">
                    {formatCurrency(trader.totalSold)}
                  </TableCell>
                  <TableCell
                    className={`text-right font-mono ${
                      trader.pnl >= 0 ? 'text-green-500' : 'text-red-500'
                    }`}
                  >
                    {trader.pnl >= 0 ? '+' : ''}{formatCurrency(trader.pnl)}
                  </TableCell>
                  <TableCell
                    className={`text-right font-mono ${
                      trader.roi >= 0 ? 'text-green-500' : 'text-red-500'
                    }`}
                  >
                    {trader.roi >= 0 ? '+' : ''}{trader.roi.toFixed(1)}%
                  </TableCell>
                  <TableCell className="text-right font-mono text-muted-foreground">
                    {trader.tradeCount > 0
                      ? formatCurrency(trader.totalBought / trader.tradeCount)
                      : '-'}
                  </TableCell>
                </TableRow>
                {expandedTrader === trader.traderAddress && (
                  <TableRow key={`${trader.traderAddress}-details`}>
                    <TableCell colSpan={7} className="bg-muted/30 p-4">
                      <TradesList trades={trader.trades} formatCurrency={formatCurrency} formatTime={formatTime} />
                    </TableCell>
                  </TableRow>
                )}
              </>
            ))}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  );
}

function TradesList({
  trades,
  formatCurrency,
  formatTime,
}: {
  trades: CopyTrade[];
  formatCurrency: (v: number) => string;
  formatTime: (t: number) => string;
}) {
  const sortedTrades = [...trades].sort((a, b) => b.timestamp - a.timestamp);

  if (trades.length === 0) {
    return <p className="text-muted-foreground">No trades</p>;
  }

  return (
    <div className="max-h-80 overflow-y-auto">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Time</TableHead>
            <TableHead>Side</TableHead>
            <TableHead>Market</TableHead>
            <TableHead className="text-right">Size</TableHead>
            <TableHead className="text-right">Price</TableHead>
            <TableHead className="text-right">Delay</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {sortedTrades.slice(0, 50).map((trade, idx) => (
            <TableRow key={idx} className="text-sm">
              <TableCell className="text-xs text-muted-foreground">
                {formatTime(trade.timestamp)}
              </TableCell>
              <TableCell>
                <span
                  className={
                    trade.side === 'BUY' ? 'text-green-500' : 'text-red-500'
                  }
                >
                  {trade.side}
                </span>
              </TableCell>
              <TableCell className="max-w-xs truncate" title={trade.title}>
                {trade.title.length > 40
                  ? trade.title.slice(0, 37) + '...'
                  : trade.title}
                <span className="text-muted-foreground ml-1">({trade.outcome})</span>
              </TableCell>
              <TableCell className="text-right font-mono">
                {formatCurrency(trade.usdcSize)}
              </TableCell>
              <TableCell className="text-right font-mono">
                {(trade.price * 100).toFixed(1)}%
              </TableCell>
              <TableCell className="text-right font-mono text-muted-foreground">
                {trade.timeDiff !== null ? `${trade.timeDiff}s` : '-'}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      {trades.length > 50 && (
        <p className="text-sm text-muted-foreground mt-2">
          Showing first 50 of {trades.length} trades
        </p>
      )}
    </div>
  );
}
