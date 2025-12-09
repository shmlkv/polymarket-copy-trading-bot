'use client';

import { useEffect, useState, useMemo } from 'react';
import { MyTradesResponse, CopyTrade, TraderCopyStats } from '@/types/myTrades';
import { CopyPnLBarChart } from '@/components/charts/CopyPnLBarChart';
import { TradesCountChart } from '@/components/charts/TradesCountChart';
import { CopyTimelineChart } from '@/components/charts/CopyTimelineChart';
import { TradesPieChart } from '@/components/charts/TradesPieChart';
import { MyTradesTable } from '@/components/MyTradesTable';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { StatusBar } from '@/components/StatusBar';

type DatePreset = '7d' | '30d' | '90d' | 'all';

export function MyTradesView() {
  const [data, setData] = useState<MyTradesResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [datePreset, setDatePreset] = useState<DatePreset>('30d');
  const [customDateFrom, setCustomDateFrom] = useState<string>('');
  const [customDateTo, setCustomDateTo] = useState<string>('');

  const fetchData = async (refresh = false) => {
    try {
      if (refresh) setRefreshing(true);
      else setLoading(true);

      const url = refresh ? '/api/my-trades?refresh=true' : '/api/my-trades';
      const res = await fetch(url);
      const json = await res.json();

      if (!res.ok) {
        throw new Error(json.error || 'Failed to fetch my trades');
      }

      setData(json);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  // Filter trades by date
  const filteredData = useMemo(() => {
    if (!data) return null;

    let startTimestamp: number;
    let endTimestamp = Date.now() / 1000;

    if (customDateFrom && customDateTo) {
      startTimestamp = new Date(customDateFrom).getTime() / 1000;
      endTimestamp = new Date(customDateTo).getTime() / 1000 + 86400; // end of day
    } else {
      const now = Date.now() / 1000;
      switch (datePreset) {
        case '7d':
          startTimestamp = now - 7 * 24 * 60 * 60;
          break;
        case '30d':
          startTimestamp = now - 30 * 24 * 60 * 60;
          break;
        case '90d':
          startTimestamp = now - 90 * 24 * 60 * 60;
          break;
        case 'all':
        default:
          startTimestamp = 0;
          break;
      }
    }

    const filteredTrades = data.allMyTrades.filter(
      (t) => t.timestamp >= startTimestamp && t.timestamp <= endTimestamp
    );

    // Recalculate byTrader stats for filtered trades
    const byTraderMap = new Map<string, CopyTrade[]>();
    byTraderMap.set('unmatched', []);
    for (const trader of data.traders) {
      byTraderMap.set(trader.address.toLowerCase(), []);
    }

    for (const trade of filteredTrades) {
      if (trade.matchedTrader) {
        const key = trade.matchedTrader.toLowerCase();
        const existing = byTraderMap.get(key) || [];
        existing.push(trade);
        byTraderMap.set(key, existing);
      } else {
        const unmatched = byTraderMap.get('unmatched') || [];
        unmatched.push(trade);
        byTraderMap.set('unmatched', unmatched);
      }
    }

    const byTrader: TraderCopyStats[] = data.traders.map((trader) => {
      const trades = byTraderMap.get(trader.address.toLowerCase()) || [];
      let totalBought = 0;
      let totalSold = 0;

      for (const trade of trades) {
        if (trade.side === 'BUY') totalBought += trade.usdcSize;
        else totalSold += trade.usdcSize;
      }

      return {
        traderAddress: trader.address,
        traderLabel: trader.label,
        trades,
        totalBought,
        totalSold,
        tradeCount: trades.length,
        pnl: totalSold - totalBought,
        roi: totalBought > 0 ? ((totalSold - totalBought) / totalBought) * 100 : 0,
      };
    });

    // Add unmatched
    const unmatchedTrades = byTraderMap.get('unmatched') || [];
    if (unmatchedTrades.length > 0) {
      let totalBought = 0;
      let totalSold = 0;
      for (const trade of unmatchedTrades) {
        if (trade.side === 'BUY') totalBought += trade.usdcSize;
        else totalSold += trade.usdcSize;
      }
      byTrader.push({
        traderAddress: 'unmatched',
        traderLabel: 'Unmatched Trades',
        trades: unmatchedTrades,
        totalBought,
        totalSold,
        tradeCount: unmatchedTrades.length,
        pnl: totalSold - totalBought,
        roi: totalBought > 0 ? ((totalSold - totalBought) / totalBought) * 100 : 0,
      });
    }

    byTrader.sort((a, b) => b.tradeCount - a.tradeCount);

    const matchedCount = filteredTrades.filter((t) => t.matchedTrader).length;

    return {
      ...data,
      allMyTrades: filteredTrades,
      byTrader,
      summary: {
        totalTrades: filteredTrades.length,
        totalBought: filteredTrades.filter((t) => t.side === 'BUY').reduce((s, t) => s + t.usdcSize, 0),
        totalSold: filteredTrades.filter((t) => t.side === 'SELL').reduce((s, t) => s + t.usdcSize, 0),
        matchedTrades: matchedCount,
        unmatchedTrades: filteredTrades.length - matchedCount,
      },
    };
  }, [data, datePreset, customDateFrom, customDateTo]);

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary mx-auto"></div>
          <p className="mt-4 text-muted-foreground">Loading your trades...</p>
          <p className="text-sm text-muted-foreground mt-2">
            This may take a moment as we fetch data from Polymarket
          </p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="text-center max-w-md">
          <h2 className="text-xl font-semibold text-red-500 mb-2">Error</h2>
          <p className="text-muted-foreground mb-4">{error}</p>
          <Button onClick={() => fetchData()}>Retry</Button>
        </div>
      </div>
    );
  }

  if (!filteredData) {
    return null;
  }

  // Use real P&L from positions if available, otherwise fallback to cash flow
  const realPnL = data?.positions?.totalPnL ?? 0;
  const unrealizedPnL = data?.positions?.unrealizedPnL ?? 0;
  const realizedPnL = data?.positions?.realizedPnL ?? 0;
  const cashFlowPnL = filteredData.byTrader.reduce((sum, t) => sum + t.pnl, 0);

  const matchRate =
    filteredData.summary.totalTrades > 0
      ? (filteredData.summary.matchedTrades / filteredData.summary.totalTrades) * 100
      : 0;

  return (
    <>
      {/* Status Bar */}
      <StatusBar
        cached={data?.cached}
        cacheDate={data?.cacheDate}
        lastUpdated={data?.analysisDate}
        totalItems={data?.allMyTrades.length}
        itemLabel="trades"
        refreshing={refreshing}
        onRefresh={() => fetchData(true)}
      />

      {/* Date Filter */}
      <Card className="mb-6 p-4">
        <div className="flex flex-col sm:flex-row sm:items-center gap-4">
          <span className="text-sm font-medium">Filter by date:</span>
          <div className="flex gap-2 flex-wrap">
            {(['7d', '30d', '90d', 'all'] as DatePreset[]).map((preset) => (
              <Button
                key={preset}
                variant={datePreset === preset && !customDateFrom ? 'default' : 'outline'}
                size="sm"
                onClick={() => {
                  setDatePreset(preset);
                  setCustomDateFrom('');
                  setCustomDateTo('');
                }}
              >
                {preset === '7d' && '7 Days'}
                {preset === '30d' && '30 Days'}
                {preset === '90d' && '90 Days'}
                {preset === 'all' && 'All Time'}
              </Button>
            ))}
          </div>
          <div className="flex items-center gap-2">
            <input
              type="date"
              value={customDateFrom}
              onChange={(e) => setCustomDateFrom(e.target.value)}
              className="bg-background border rounded px-2 py-1 text-sm"
            />
            <span className="text-muted-foreground">to</span>
            <input
              type="date"
              value={customDateTo}
              onChange={(e) => setCustomDateTo(e.target.value)}
              className="bg-background border rounded px-2 py-1 text-sm"
            />
          </div>
        </div>
      </Card>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
        <div className="bg-card rounded-lg p-4 border">
          <p className="text-sm text-muted-foreground">My Wallet</p>
          <p className="text-sm font-mono truncate" title={filteredData.myWallet}>
            {filteredData.myWallet.slice(0, 8)}...{filteredData.myWallet.slice(-6)}
          </p>
        </div>
        <div className="bg-card rounded-lg p-4 border">
          <p className="text-sm text-muted-foreground">Total Trades (filtered)</p>
          <p className="text-2xl font-bold">{filteredData.summary.totalTrades}</p>
        </div>
        <div className="bg-card rounded-lg p-4 border">
          <p className="text-sm text-muted-foreground">Total Bought</p>
          <p className="text-2xl font-bold">${filteredData.summary.totalBought.toFixed(2)}</p>
        </div>
        <div className="bg-card rounded-lg p-4 border">
          <p className="text-sm text-muted-foreground">Match Rate</p>
          <p className="text-2xl font-bold">{matchRate.toFixed(1)}%</p>
          <p className="text-xs text-muted-foreground">
            {filteredData.summary.matchedTrades} / {filteredData.summary.totalTrades}
          </p>
        </div>
      </div>

      {/* P&L Cards - Real data from positions */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
        <div className="bg-card rounded-lg p-4 border">
          <p className="text-sm text-muted-foreground">Total P&L (Real)</p>
          <p
            className={`text-2xl font-bold ${
              realPnL >= 0 ? 'text-green-500' : 'text-red-500'
            }`}
          >
            {realPnL >= 0 ? '+' : '-'}${Math.abs(realPnL).toFixed(2)}
          </p>
        </div>
        <div className="bg-card rounded-lg p-4 border">
          <p className="text-sm text-muted-foreground">Unrealized P&L</p>
          <p
            className={`text-2xl font-bold ${
              unrealizedPnL >= 0 ? 'text-green-500' : 'text-red-500'
            }`}
          >
            {unrealizedPnL >= 0 ? '+' : '-'}${Math.abs(unrealizedPnL).toFixed(2)}
          </p>
        </div>
        <div className="bg-card rounded-lg p-4 border">
          <p className="text-sm text-muted-foreground">Realized P&L</p>
          <p
            className={`text-2xl font-bold ${
              realizedPnL >= 0 ? 'text-green-500' : 'text-red-500'
            }`}
          >
            {realizedPnL >= 0 ? '+' : '-'}${Math.abs(realizedPnL).toFixed(2)}
          </p>
        </div>
        <div className="bg-card rounded-lg p-4 border">
          <p className="text-sm text-muted-foreground">Positions Value</p>
          <p className="text-2xl font-bold">
            ${(data?.positions?.totalValue ?? 0).toFixed(2)}
          </p>
        </div>
      </div>

      {/* Cash Flow info (for reference) */}
      <Card className="mb-6 p-4">
        <div className="flex items-center gap-4 text-sm">
          <span className="text-muted-foreground">Cash Flow (Sold - Bought):</span>
          <span className={cashFlowPnL >= 0 ? 'text-green-500' : 'text-red-500'}>
            {cashFlowPnL >= 0 ? '+' : '-'}${Math.abs(cashFlowPnL).toFixed(2)}
          </span>
          <span className="text-muted-foreground">|</span>
          <span className="text-muted-foreground">Total Sold:</span>
          <span>${filteredData.summary.totalSold.toFixed(2)}</span>
          <span className="text-muted-foreground">|</span>
          <span className="text-muted-foreground">Positions:</span>
          <span>{data?.positions?.total ?? 0}</span>
        </div>
      </Card>

      {/* Charts Row 1 */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
        <CopyPnLBarChart byTrader={filteredData.byTrader} />
        <TradesPieChart byTrader={filteredData.byTrader} />
      </div>

      {/* Charts Row 2 */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
        <TradesCountChart byTrader={filteredData.byTrader} />
        <CopyTimelineChart trades={filteredData.allMyTrades} />
      </div>

      {/* Table */}
      <MyTradesTable byTrader={filteredData.byTrader} />
    </>
  );
}
