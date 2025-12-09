import { NextResponse } from 'next/server';
import * as fs from 'fs';
import * as path from 'path';

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const refresh = searchParams.get('refresh') === 'true';

  try {
    const reportsDir = path.join(process.cwd(), '..', 'trader_reports');
    const myTradesPath = path.join(reportsDir, '_MY_TRADES.json');

    // Check if cached data exists
    if (fs.existsSync(myTradesPath) && !refresh) {
      const data = JSON.parse(fs.readFileSync(myTradesPath, 'utf-8'));
      return NextResponse.json({
        ...data,
        cached: true,
        cacheDate: data.analysisDate,
      });
    }

    // If no cache or refresh requested, fetch live data
    return await fetchLiveData(reportsDir);
  } catch (error) {
    console.error('Error fetching my trades:', error);
    return NextResponse.json(
      { error: 'Failed to fetch my trades' },
      { status: 500 }
    );
  }
}

async function fetchLiveData(reportsDir: string) {
  const summaryPath = path.join(reportsDir, '_SUMMARY.json');

  if (!fs.existsSync(summaryPath)) {
    return NextResponse.json(
      { error: 'Run npm run analyze first to generate trader data' },
      { status: 404 }
    );
  }

  const summaryData = JSON.parse(fs.readFileSync(summaryPath, 'utf-8'));

  const formatWalletLabel = (address: string): string => `0x...${address.slice(-4)}`;

  // Find my wallet
  const myWalletData = summaryData.find((t: { label: string }) =>
    t.label.includes('МОЙ') || t.label.includes('MY') || t.label.includes('My Wallet')
  ) || summaryData[0];

  const myWallet = myWalletData?.address;

  if (!myWallet) {
    return NextResponse.json(
      { error: 'Could not determine my wallet address' },
      { status: 400 }
    );
  }

  // Get trader addresses - use proper wallet format if label is like "Trader X"
  const traders = summaryData
    .filter((t: { address: string }) => t.address.toLowerCase() !== myWallet.toLowerCase())
    .map((t: { address: string; label: string }) => ({
      address: t.address,
      label: t.label.startsWith('Trader ') ? formatWalletLabel(t.address) : t.label,
    }));

  // Fetch ALL my trades and positions
  const [myTrades, myPositions] = await Promise.all([
    fetchTrades(myWallet),
    fetchPositions(myWallet),
  ]);

  // Calculate real P&L from positions
  const totalUnrealizedPnL = myPositions.reduce((sum, p) => sum + (p.cashPnl || 0), 0);
  const totalRealizedPnL = myPositions.reduce((sum, p) => sum + (p.realizedPnl || 0), 0);
  const totalPositionsPnL = totalUnrealizedPnL + totalRealizedPnL;

  // Fetch ALL traders' trades
  const traderTradesMap = new Map<string, Trade[]>();
  for (const trader of traders) {
    const trades = await fetchTrades(trader.address);
    traderTradesMap.set(trader.address.toLowerCase(), trades);
  }

  // Match trades
  const MATCH_WINDOW_SECONDS = 300;

  const allMyTrades = myTrades.map(myTrade => {
    let matchedTrader: string | null = null;
    let matchedTraderLabel: string | null = null;
    let timeDiff: number | null = null;

    for (const trader of traders) {
      const traderTrades = traderTradesMap.get(trader.address.toLowerCase()) || [];
      const match = traderTrades.find(tt =>
        tt.conditionId === myTrade.conditionId &&
        tt.side === myTrade.side &&
        tt.timestamp < myTrade.timestamp &&
        myTrade.timestamp - tt.timestamp <= MATCH_WINDOW_SECONDS
      );

      if (match) {
        matchedTrader = trader.address;
        matchedTraderLabel = trader.label;
        timeDiff = myTrade.timestamp - match.timestamp;
        break;
      }
    }

    return { ...myTrade, matchedTrader, matchedTraderLabel, timeDiff };
  });

  // Group by trader
  const byTraderMap = new Map<string, typeof allMyTrades>();
  byTraderMap.set('unmatched', []);
  for (const trader of traders) {
    byTraderMap.set(trader.address.toLowerCase(), []);
  }

  for (const trade of allMyTrades) {
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

  // Calculate stats
  const byTrader = traders.map((trader: { address: string; label: string }) => {
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

  byTrader.sort((a: { tradeCount: number }, b: { tradeCount: number }) => b.tradeCount - a.tradeCount);

  const matchedCount = allMyTrades.filter(t => t.matchedTrader).length;

  const result = {
    myWallet,
    analysisDate: new Date().toISOString(),
    traders,
    allMyTrades,
    byTrader,
    positions: {
      total: myPositions.length,
      totalValue: myPositions.reduce((s, p) => s + (p.currentValue || 0), 0),
      unrealizedPnL: totalUnrealizedPnL,
      realizedPnL: totalRealizedPnL,
      totalPnL: totalPositionsPnL,
    },
    summary: {
      totalTrades: allMyTrades.length,
      totalBought: allMyTrades.filter(t => t.side === 'BUY').reduce((s, t) => s + t.usdcSize, 0),
      totalSold: allMyTrades.filter(t => t.side === 'SELL').reduce((s, t) => s + t.usdcSize, 0),
      matchedTrades: matchedCount,
      unmatchedTrades: allMyTrades.length - matchedCount,
    },
    cached: false,
  };

  // Save to cache
  const myTradesPath = path.join(reportsDir, '_MY_TRADES.json');
  fs.writeFileSync(myTradesPath, JSON.stringify(result, null, 2));

  return NextResponse.json(result);
}

interface Trade {
  timestamp: number;
  side: 'BUY' | 'SELL';
  usdcSize: number;
  price: number;
  title: string;
  outcome: string;
  conditionId: string;
  asset: string;
}

interface Position {
  asset: string;
  conditionId: string;
  size: number;
  avgPrice: number;
  initialValue: number;
  currentValue: number;
  cashPnl: number;
  percentPnl: number;
  realizedPnl: number;
  curPrice: number;
  title: string;
  outcome: string;
}

async function fetchPositions(address: string): Promise<Position[]> {
  const url = `https://data-api.polymarket.com/positions?user=${address}`;
  const response = await fetch(url);
  const data = await response.json();
  return Array.isArray(data) ? data : [];
}

async function fetchTrades(address: string): Promise<Trade[]> {
  const allTrades: Trade[] = [];
  let offset = 0;
  const limit = 500;

  while (true) {
    const url = `https://data-api.polymarket.com/activity?user=${address}&type=TRADE&limit=${limit}&offset=${offset}`;
    const response = await fetch(url);
    const trades = await response.json();

    if (!Array.isArray(trades) || trades.length === 0) break;
    allTrades.push(...trades);
    if (trades.length < limit) break;
    offset += limit;
    // No limit - fetch all trades
  }

  return allTrades;
}
