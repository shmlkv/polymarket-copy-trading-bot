'use client';

import { useEffect, useState } from 'react';
import { TraderAnalysis } from '@/types/trader';
import { PnLBarChart } from '@/components/charts/PnLBarChart';
import { ROIBarChart } from '@/components/charts/ROIBarChart';
import { MonthlyLineChart } from '@/components/charts/MonthlyLineChart';
import { VolumeLineChart } from '@/components/charts/VolumeLineChart';
import { DailyLineChart } from '@/components/charts/DailyLineChart';
import { TradersTable } from '@/components/TradersTable';
import { MyTradesView } from '@/components/MyTradesView';
import { SettingsView } from '@/components/SettingsView';
import { StatusBar } from '@/components/StatusBar';
import { Button } from '@/components/ui/button';

type ViewMode = 'traders' | 'my-trades' | 'settings';

export default function Home() {
  const [viewMode, setViewMode] = useState<ViewMode>('traders');
  const [traders, setTraders] = useState<TraderAnalysis[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchTraders = async (refresh = false) => {
    try {
      if (refresh) {
        setRefreshing(true);
      }
      const url = refresh ? '/api/traders?refresh=true' : '/api/traders';
      const res = await fetch(url);
      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error || 'Failed to fetch traders');
      }

      setTraders(data.traders);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchTraders();
  }, []);

  // Show loading only for traders view initial load
  if (loading && viewMode === 'traders') {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary mx-auto"></div>
          <p className="mt-4 text-muted-foreground">Loading trader data...</p>
        </div>
      </div>
    );
  }

  // Show error only for traders view
  if (error && viewMode === 'traders') {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="text-center max-w-md">
          <h2 className="text-xl font-semibold text-red-500 mb-2">Error</h2>
          <p className="text-muted-foreground mb-4">{error}</p>
          <p className="text-sm text-muted-foreground mb-4">
            Make sure to run <code className="bg-muted px-2 py-1 rounded">npm run analyze</code> first
            to generate trader reports.
          </p>
          <div className="flex gap-2 justify-center">
            <Button onClick={() => fetchTraders()}>Retry</Button>
            <Button variant="outline" onClick={() => setViewMode('settings')}>
              Go to Settings
            </Button>
          </div>
        </div>
      </div>
    );
  }

  // Calculate summary stats for traders view
  const totalPnL = traders.reduce((sum, t) => sum + t.pnl.total, 0);
  const totalVolume = traders.reduce((sum, t) => sum + t.volume.totalBought, 0);
  const avgWinRate =
    traders.length > 0
      ? traders.reduce((sum, t) => sum + t.positions.winRate, 0) / traders.length
      : 0;
  const profitableTraders = traders.filter((t) => t.pnl.total > 0).length;

  const getSubtitle = () => {
    switch (viewMode) {
      case 'traders':
        return (
          <>
            Analyzing {traders.length} traders | Last updated:{' '}
            {traders[0]?.analysisDate?.split('T')[0] || 'N/A'}
          </>
        );
      case 'my-trades':
        return <>My Copy Trading Performance</>;
      case 'settings':
        return <>Configure bot settings and execute actions</>;
    }
  };

  return (
    <div className="min-h-screen bg-background dark">
      <div className="container mx-auto px-4 py-8">
        {/* Header with Mode Toggle */}
        <header className="mb-8">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-4">
            <div>
              <h1 className="text-3xl font-bold mb-2">
                {viewMode === 'settings' ? 'Bot Dashboard' : 'Trader Analytics Dashboard'}
              </h1>
              <p className="text-muted-foreground">{getSubtitle()}</p>
            </div>

            {/* Mode Toggle Buttons */}
            <div className="flex gap-2">
              <Button
                variant={viewMode === 'traders' ? 'default' : 'outline'}
                onClick={() => setViewMode('traders')}
              >
                Traders Analysis
              </Button>
              <Button
                variant={viewMode === 'my-trades' ? 'default' : 'outline'}
                onClick={() => setViewMode('my-trades')}
              >
                My Trades
              </Button>
              <Button
                variant={viewMode === 'settings' ? 'default' : 'outline'}
                onClick={() => setViewMode('settings')}
              >
                Settings
              </Button>
            </div>
          </div>
        </header>

        {viewMode === 'traders' && (
          <>
            {/* Status Bar */}
            <StatusBar
              lastUpdated={traders[0]?.analysisDate}
              totalItems={traders.length}
              itemLabel="traders"
              refreshing={refreshing}
              onRefresh={() => fetchTraders(true)}
            />

            {/* Summary Cards */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
              <div className="bg-card rounded-lg p-4 border">
                <p className="text-sm text-muted-foreground">Total P&L</p>
                <p
                  className={`text-2xl font-bold font-mono ${
                    totalPnL >= 0 ? 'text-green-500' : 'text-red-500'
                  }`}
                >
                  {totalPnL >= 0 ? '+' : '-'}${Math.abs(totalPnL).toFixed(2)}
                </p>
              </div>
              <div className="bg-card rounded-lg p-4 border">
                <p className="text-sm text-muted-foreground">Total Volume</p>
                <p className="text-2xl font-bold font-mono">${totalVolume.toFixed(0)}</p>
              </div>
              <div className="bg-card rounded-lg p-4 border">
                <p className="text-sm text-muted-foreground">Avg Win Rate</p>
                <p className="text-2xl font-bold font-mono">{avgWinRate.toFixed(1)}%</p>
              </div>
              <div className="bg-card rounded-lg p-4 border">
                <p className="text-sm text-muted-foreground">Profitable Traders</p>
                <p className="text-2xl font-bold font-mono">
                  {profitableTraders}/{traders.length}
                </p>
              </div>
            </div>

            {/* Charts */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
              <PnLBarChart traders={traders} />
              <ROIBarChart traders={traders} />
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
              <MonthlyLineChart traders={traders} />
              <VolumeLineChart traders={traders} />
            </div>

            <div className="grid grid-cols-1 gap-6 mb-8">
              <DailyLineChart traders={traders} />
            </div>

            {/* Table */}
            <TradersTable traders={traders} />
          </>
        )}

        {viewMode === 'my-trades' && <MyTradesView />}

        {viewMode === 'settings' && <SettingsView />}
      </div>
    </div>
  );
}
