'use client';

import { useEffect, useState } from 'react';
import { TraderAnalysis } from '@/types/trader';
import { PnLBarChart } from '@/components/charts/PnLBarChart';
import { ROIBarChart } from '@/components/charts/ROIBarChart';
import { MonthlyLineChart } from '@/components/charts/MonthlyLineChart';
import { VolumeLineChart } from '@/components/charts/VolumeLineChart';
import { DailyLineChart } from '@/components/charts/DailyLineChart';
import { WinRateGauge } from '@/components/charts/WinRateGauge';
import { ProfitLossDonut } from '@/components/charts/ProfitLossDonut';
import { VolumeSparkline } from '@/components/charts/VolumeSparkline';
import { TrendArrow } from '@/components/charts/TrendArrow';
import { RiskScoreMeter } from '@/components/charts/RiskScoreMeter';
import { ActivePositionsPie } from '@/components/charts/ActivePositionsPie';
import { TradersTable } from '@/components/TradersTable';
import { MyTradesView } from '@/components/MyTradesView';
import { SettingsView } from '@/components/SettingsView';
import { StatusBar } from '@/components/StatusBar';
import { Button } from '@/components/ui/button';
import { TimeRangeFilter, TimeRange } from '@/components/TimeRangeFilter';

type ViewMode = 'traders' | 'my-trades' | 'settings';

export default function Home() {
  const [viewMode, setViewMode] = useState<ViewMode>('traders');
  const [traders, setTraders] = useState<TraderAnalysis[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [timeRange, setTimeRange] = useState<TimeRange>('30d');

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
      <div className="container mx-auto px-4 py-6">
        {/* Header with Mode Toggle */}
        <header className="mb-6">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-4">
            <div>
              <h1 className="text-3xl font-bold mb-1 tracking-tight">
                {viewMode === 'settings' ? 'Bot Dashboard' : 'Trader Analytics'}
              </h1>
              <p className="text-sm text-muted-foreground">{getSubtitle()}</p>
            </div>

            {/* Mode Toggle Buttons */}
            <div className="flex gap-2">
              <Button
                size="sm"
                variant={viewMode === 'traders' ? 'default' : 'outline'}
                onClick={() => setViewMode('traders')}
              >
                Traders
              </Button>
              <Button
                size="sm"
                variant={viewMode === 'my-trades' ? 'default' : 'outline'}
                onClick={() => setViewMode('my-trades')}
              >
                My Trades
              </Button>
              <Button
                size="sm"
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
            {/* Status Bar with Time Range Filter */}
            <div className="mb-4 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
              <StatusBar
                lastUpdated={traders[0]?.analysisDate}
                totalItems={traders.length}
                itemLabel="traders"
                refreshing={refreshing}
                onRefresh={() => fetchTraders(true)}
              />
              <TimeRangeFilter value={timeRange} onChange={setTimeRange} />
            </div>

            {/* Hero Section - Bento Grid */}
            <div className="grid grid-cols-12 gap-3 mb-6" style={{ minHeight: '320px' }}>
              {/* P&L Chart - Left */}
              <div className="col-span-12 lg:col-span-4">
                <PnLBarChart traders={traders} compact timeRange={timeRange} />
              </div>

              {/* Center Column - 2x2 Grid of small widgets */}
              <div className="col-span-12 lg:col-span-4 grid grid-cols-2 gap-3">
                <WinRateGauge traders={traders} timeRange={timeRange} />
                <ProfitLossDonut traders={traders} timeRange={timeRange} />
                <VolumeSparkline traders={traders} timeRange={timeRange} />
                <TrendArrow traders={traders} timeRange={timeRange} />
              </div>

              {/* ROI Chart - Right */}
              <div className="col-span-12 lg:col-span-4">
                <ROIBarChart traders={traders} compact timeRange={timeRange} />
              </div>
            </div>

            {/* Second Row - Time Series Charts */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-6">
              <DailyLineChart traders={traders} compact timeRange={timeRange} />
              <MonthlyLineChart traders={traders} compact timeRange={timeRange} />
            </div>

            {/* Third Row - Additional Metrics + Table Preview */}
            <div className="grid grid-cols-12 gap-4 mb-6">
              <div className="col-span-6 lg:col-span-2">
                <RiskScoreMeter traders={traders} timeRange={timeRange} />
              </div>
              <div className="col-span-6 lg:col-span-2">
                <ActivePositionsPie traders={traders} timeRange={timeRange} />
              </div>
              <div className="col-span-12 lg:col-span-8">
                <VolumeLineChart traders={traders} compact timeRange={timeRange} />
              </div>
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
