import { ENV } from '../config/env';
import fetchData from '../utils/fetchData';
import * as fs from 'fs';
import * as path from 'path';

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

interface CopyTrade extends Trade {
    matchedTrader: string | null;
    matchedTraderLabel: string | null;
    timeDiff: number | null;
}

interface TraderCopyStats {
    traderAddress: string;
    traderLabel: string;
    trades: CopyTrade[];
    totalBought: number;
    totalSold: number;
    tradeCount: number;
    pnl: number;
    roi: number;
}

interface MyTradesData {
    myWallet: string;
    analysisDate: string;
    traders: { address: string; label: string }[];
    allMyTrades: CopyTrade[];
    byTrader: TraderCopyStats[];
    summary: {
        totalTrades: number;
        totalBought: number;
        totalSold: number;
        matchedTrades: number;
        unmatchedTrades: number;
    };
}

const fetchTrades = async (address: string): Promise<Trade[]> => {
    const allTrades: Trade[] = [];
    let offset = 0;
    const limit = 500;

    while (true) {
        const url = `https://data-api.polymarket.com/activity?user=${address}&type=TRADE&limit=${limit}&offset=${offset}`;
        const trades = await fetchData(url);

        if (!Array.isArray(trades) || trades.length === 0) break;

        allTrades.push(...trades);
        if (trades.length < limit) break;
        offset += limit;
        if (offset > 10000) break;
    }

    return allTrades;
};

const fetchProfile = async (address: string): Promise<{ username?: string } | null> => {
    try {
        const url = `https://data-api.polymarket.com/users/${address}`;
        return await fetchData(url);
    } catch {
        return null;
    }
};

const main = async () => {
    console.log('🔍 АНАЛИЗ МОИХ КОПИ-ТРЕЙДОВ');
    console.log('═'.repeat(60));

    const myWallet = ENV.PROXY_WALLET;
    const tradersToFollow = ENV.USER_ADDRESSES;

    console.log(`\nМой кошелёк: ${myWallet}`);
    console.log(`Трейдеров для анализа: ${tradersToFollow.length}`);

    const formatWalletLabel = (address: string): string => {
        return `0x...${address.slice(-4)}`;
    };

    // Get trader labels
    const traders: { address: string; label: string }[] = [];
    for (let i = 0; i < tradersToFollow.length; i++) {
        const address = tradersToFollow[i];
        const profile = await fetchProfile(address);
        const label = profile?.username ? `@${profile.username}` : formatWalletLabel(address);
        traders.push({ address, label });
        console.log(`  ${i + 1}. ${label}: ${address.slice(0, 10)}...`);
    }

    // Fetch ALL my trades (no date filter - filter on frontend)
    console.log('\n📊 Загрузка моих сделок...');
    const myTrades = await fetchTrades(myWallet);
    console.log(`   Всего сделок за всё время: ${myTrades.length}`);

    // Fetch ALL traders' trades
    console.log('\n📊 Загрузка сделок трейдеров...');
    const traderTradesMap = new Map<string, Trade[]>();

    for (const trader of traders) {
        const trades = await fetchTrades(trader.address);
        traderTradesMap.set(trader.address.toLowerCase(), trades);
        console.log(`   ${trader.label}: ${trades.length} сделок`);
    }

    // Match trades
    console.log('\n🔗 Сопоставление сделок...');
    const MATCH_WINDOW_SECONDS = 300; // 5 minutes

    const allMyTrades: CopyTrade[] = myTrades.map((myTrade) => {
        let matchedTrader: string | null = null;
        let matchedTraderLabel: string | null = null;
        let timeDiff: number | null = null;

        for (const trader of traders) {
            const traderTrades = traderTradesMap.get(trader.address.toLowerCase()) || [];

            const match = traderTrades.find(
                (tt) =>
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

        return {
            ...myTrade,
            matchedTrader,
            matchedTraderLabel,
            timeDiff,
        };
    });

    // Group by trader
    const byTraderMap = new Map<string, CopyTrade[]>();
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
    const byTrader: TraderCopyStats[] = traders.map((trader) => {
        const trades = byTraderMap.get(trader.address.toLowerCase()) || [];

        let totalBought = 0;
        let totalSold = 0;

        for (const trade of trades) {
            if (trade.side === 'BUY') {
                totalBought += trade.usdcSize;
            } else {
                totalSold += trade.usdcSize;
            }
        }

        const pnl = totalSold - totalBought;
        const roi = totalBought > 0 ? (pnl / totalBought) * 100 : 0;

        return {
            traderAddress: trader.address,
            traderLabel: trader.label,
            trades,
            totalBought,
            totalSold,
            tradeCount: trades.length,
            pnl,
            roi,
        };
    });

    // Add unmatched
    const unmatchedTrades = byTraderMap.get('unmatched') || [];
    if (unmatchedTrades.length > 0) {
        let totalBought = 0;
        let totalSold = 0;
        for (const trade of unmatchedTrades) {
            if (trade.side === 'BUY') {
                totalBought += trade.usdcSize;
            } else {
                totalSold += trade.usdcSize;
            }
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

    const matchedCount = allMyTrades.filter((t) => t.matchedTrader).length;

    const result: MyTradesData = {
        myWallet,
        analysisDate: new Date().toISOString(),
        traders,
        allMyTrades,
        byTrader,
        summary: {
            totalTrades: allMyTrades.length,
            totalBought: allMyTrades.filter((t) => t.side === 'BUY').reduce((s, t) => s + t.usdcSize, 0),
            totalSold: allMyTrades.filter((t) => t.side === 'SELL').reduce((s, t) => s + t.usdcSize, 0),
            matchedTrades: matchedCount,
            unmatchedTrades: allMyTrades.length - matchedCount,
        },
    };

    // Save to JSON
    const outputDir = path.join(process.cwd(), 'trader_reports');
    if (!fs.existsSync(outputDir)) {
        fs.mkdirSync(outputDir, { recursive: true });
    }

    const outputPath = path.join(outputDir, '_MY_TRADES.json');
    fs.writeFileSync(outputPath, JSON.stringify(result, null, 2));

    // Print summary
    console.log('\n' + '═'.repeat(60));
    console.log('📊 РЕЗУЛЬТАТЫ');
    console.log('═'.repeat(60));
    console.log(`Всего моих сделок: ${result.summary.totalTrades}`);
    console.log(`Сопоставлено: ${result.summary.matchedTrades} (${((matchedCount / allMyTrades.length) * 100).toFixed(1)}%)`);
    console.log(`Не сопоставлено: ${result.summary.unmatchedTrades}`);
    console.log(`\nОбъём покупок: $${result.summary.totalBought.toFixed(2)}`);
    console.log(`Объём продаж: $${result.summary.totalSold.toFixed(2)}`);

    const totalPnL = byTrader.reduce((s, t) => s + t.pnl, 0);
    console.log(`\nОбщий P&L: $${totalPnL.toFixed(2)}`);

    console.log('\n📊 P&L ПО ТРЕЙДЕРАМ:');
    console.log('─'.repeat(60));
    for (const t of byTrader) {
        if (t.tradeCount === 0) continue;
        const pnlStr = t.pnl >= 0 ? `+$${t.pnl.toFixed(2)}` : `-$${Math.abs(t.pnl).toFixed(2)}`;
        console.log(`${t.traderLabel.padEnd(20)} | ${String(t.tradeCount).padStart(4)} trades | ${pnlStr.padStart(12)} | ${t.roi.toFixed(1)}%`);
    }

    console.log('\n✅ Сохранено в:', outputPath);
};

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error('❌ Ошибка:', error);
        process.exit(1);
    });
