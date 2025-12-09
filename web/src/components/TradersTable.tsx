'use client';

import { useState } from 'react';
import { TraderAnalysis } from '@/types/trader';
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
import { TraderDetails } from './TraderDetails';

interface TradersTableProps {
  traders: TraderAnalysis[];
}

type SortKey = 'label' | 'pnl' | 'roi' | 'winRate' | 'volume' | 'trades';
type SortDir = 'asc' | 'desc';
type FilterMode = 'all' | 'profitable' | 'losing' | 'active';

export function TradersTable({ traders }: TradersTableProps) {
  const [sortKey, setSortKey] = useState<SortKey>('pnl');
  const [sortDir, setSortDir] = useState<SortDir>('desc');
  const [expandedTrader, setExpandedTrader] = useState<string | null>(null);
  const [filterMode, setFilterMode] = useState<FilterMode>('all');
  const [hideMyWallet, setHideMyWallet] = useState(false);

  const handleSort = (key: SortKey) => {
    if (sortKey === key) {
      setSortDir(sortDir === 'asc' ? 'desc' : 'asc');
    } else {
      setSortKey(key);
      setSortDir('desc');
    }
  };

  // Filter traders
  let filteredTraders = [...traders];

  if (hideMyWallet) {
    filteredTraders = filteredTraders.filter(
      t => !t.label.includes('My Wallet') && !t.label.includes('МОЙ')
    );
  }

  switch (filterMode) {
    case 'profitable':
      filteredTraders = filteredTraders.filter(t => t.pnl.total > 0);
      break;
    case 'losing':
      filteredTraders = filteredTraders.filter(t => t.pnl.total < 0);
      break;
    case 'active':
      filteredTraders = filteredTraders.filter(t => t.trades.total > 10);
      break;
  }

  // Sort traders
  const sortedTraders = filteredTraders.sort((a, b) => {
    let aVal: number | string;
    let bVal: number | string;

    switch (sortKey) {
      case 'label':
        aVal = a.label.toLowerCase();
        bVal = b.label.toLowerCase();
        break;
      case 'pnl':
        aVal = a.pnl.total;
        bVal = b.pnl.total;
        break;
      case 'roi':
        aVal = a.pnl.roi;
        bVal = b.pnl.roi;
        break;
      case 'winRate':
        aVal = a.positions.winRate;
        bVal = b.positions.winRate;
        break;
      case 'volume':
        aVal = a.volume.totalBought;
        bVal = b.volume.totalBought;
        break;
      case 'trades':
        aVal = a.trades.total;
        bVal = b.trades.total;
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

  return (
    <Card>
      <CardHeader>
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <CardTitle>Traders Overview</CardTitle>
          <div className="flex flex-wrap gap-2">
            <Button
              variant={filterMode === 'all' ? 'default' : 'outline'}
              size="sm"
              onClick={() => setFilterMode('all')}
            >
              All ({traders.length})
            </Button>
            <Button
              variant={filterMode === 'profitable' ? 'default' : 'outline'}
              size="sm"
              onClick={() => setFilterMode('profitable')}
              className="text-green-500 border-green-500/50"
            >
              Profitable
            </Button>
            <Button
              variant={filterMode === 'losing' ? 'default' : 'outline'}
              size="sm"
              onClick={() => setFilterMode('losing')}
              className="text-red-500 border-red-500/50"
            >
              Losing
            </Button>
            <Button
              variant={filterMode === 'active' ? 'default' : 'outline'}
              size="sm"
              onClick={() => setFilterMode('active')}
            >
              Active (10+)
            </Button>
            <Button
              variant={hideMyWallet ? 'default' : 'outline'}
              size="sm"
              onClick={() => setHideMyWallet(!hideMyWallet)}
            >
              {hideMyWallet ? 'Show My Wallet' : 'Hide My Wallet'}
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>
                <SortButton label="Trader" sortKeyName="label" />
              </TableHead>
              <TableHead className="text-right">
                <SortButton label="P&L" sortKeyName="pnl" />
              </TableHead>
              <TableHead className="text-right">
                <SortButton label="ROI %" sortKeyName="roi" />
              </TableHead>
              <TableHead className="text-right">
                <SortButton label="Win Rate" sortKeyName="winRate" />
              </TableHead>
              <TableHead className="text-right">
                <SortButton label="Volume" sortKeyName="volume" />
              </TableHead>
              <TableHead className="text-right">
                <SortButton label="Trades" sortKeyName="trades" />
              </TableHead>
              <TableHead className="text-right">Positions</TableHead>
              <TableHead className="text-right">Monthly ROI</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {sortedTraders.map((trader) => (
              <>
                <TableRow
                  key={trader.address}
                  className="cursor-pointer hover:bg-muted/50"
                  onClick={() =>
                    setExpandedTrader(
                      expandedTrader === trader.address ? null : trader.address
                    )
                  }
                >
                  <TableCell className="font-medium">
                    <div className="flex items-center gap-2">
                      <span>{expandedTrader === trader.address ? '▼' : '▶'}</span>
                      <div>
                        <div>{trader.label}</div>
                        <div className="text-xs text-muted-foreground">
                          {trader.address.slice(0, 6)}...{trader.address.slice(-4)}
                        </div>
                      </div>
                    </div>
                  </TableCell>
                  <TableCell
                    className={`text-right font-mono ${
                      trader.pnl.total >= 0 ? 'text-green-500' : 'text-red-500'
                    }`}
                  >
                    {trader.pnl.total >= 0 ? '+' : ''}{formatCurrency(trader.pnl.total)}
                  </TableCell>
                  <TableCell
                    className={`text-right font-mono ${
                      trader.pnl.roi >= 0 ? 'text-green-500' : 'text-red-500'
                    }`}
                  >
                    {trader.pnl.roi >= 0 ? '+' : ''}{trader.pnl.roi.toFixed(1)}%
                  </TableCell>
                  <TableCell className="text-right font-mono">
                    {trader.positions.winRate.toFixed(1)}%
                  </TableCell>
                  <TableCell className="text-right font-mono">
                    {formatCurrency(trader.volume.totalBought)}
                  </TableCell>
                  <TableCell className="text-right font-mono">
                    {trader.trades.total}
                  </TableCell>
                  <TableCell className="text-right">
                    <span className="text-green-500">{trader.positions.winners}</span>
                    {' / '}
                    <span className="text-red-500">{trader.positions.losers}</span>
                    <span className="text-muted-foreground text-xs ml-1">
                      ({trader.positions.open} open)
                    </span>
                  </TableCell>
                  <TableCell
                    className={`text-right font-mono ${
                      trader.pnl.monthlyRoi >= 0 ? 'text-green-500' : 'text-red-500'
                    }`}
                  >
                    {trader.pnl.monthlyRoi >= 0 ? '+' : ''}{trader.pnl.monthlyRoi.toFixed(1)}%
                  </TableCell>
                </TableRow>
                {expandedTrader === trader.address && (
                  <TableRow key={`${trader.address}-details`}>
                    <TableCell colSpan={8} className="bg-muted/30 p-4">
                      <TraderDetails trader={trader} />
                    </TableCell>
                  </TableRow>
                )}
              </>
            ))}
          </TableBody>
        </Table>
        {sortedTraders.length === 0 && (
          <p className="text-center text-muted-foreground py-8">
            No traders match the current filter
          </p>
        )}
      </CardContent>
    </Card>
  );
}
