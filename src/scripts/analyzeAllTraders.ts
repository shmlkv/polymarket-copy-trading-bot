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
    redeemable: boolean;
}

interface MonthlyStats {
    month: string;
    totalBought: number;
    totalSold: number;
    netFlow: number;
    tradeCount: number;
    buyCount: number;
    sellCount: number;
}

interface TraderAnalysis {
    address: string;
    label: string;
    analysisDate: string;
    periodMonths: number;
    trades: {
        total: number;
        buys: number;
        sells: number;
        firstTrade: string;
        lastTrade: string;
        daysActive: number;
    };
    volume: {
        totalBought: number;
        totalSold: number;
        netFlow: number;
    };
    positions: {
        total: number;
        open: number;
        winners: number;
        losers: number;
        winRate: number;
        initialValue: number;
        currentValue: number;
    };
    pnl: {
        unrealized: number;
        realized: number;
        total: number;
        roi: number;
        monthlyRoi: number;
        annualizedRoi: number;
    };
    redeemable: {
        count: number;
        value: number;
    };
    monthlyBreakdown: MonthlyStats[];
    topWinners: { title: string; outcome: string; pnl: number; roi: number }[];
    topLosers: { title: string; outcome: string; pnl: number; roi: number }[];
}

const formatMonth = (timestamp: number): string => {
    const date = new Date(timestamp * 1000);
    return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}`;
};

const formatDate = (timestamp: number): string => {
    const date = new Date(timestamp * 1000);
    return date.toISOString().split('T')[0];
};

const fetchTrades = async (address: string): Promise<Trade[]> => {
    const url = `https://data-api.polymarket.com/activity?user=${address}&type=TRADE&limit=1000`;
    const trades = await fetchData(url);
    return Array.isArray(trades) ? trades : [];
};

const fetchPositions = async (address: string): Promise<Position[]> => {
    const url = `https://data-api.polymarket.com/positions?user=${address}`;
    const data = await fetchData(url);
    return Array.isArray(data) ? data : [];
};

const fetchProfile = async (address: string): Promise<{ name?: string; username?: string } | null> => {
    try {
        const url = `https://data-api.polymarket.com/users/${address}`;
        return await fetchData(url);
    } catch {
        return null;
    }
};

const analyzeTrader = async (address: string, label: string): Promise<TraderAnalysis> => {
    console.log(`\n📊 Анализ: ${label}`);
    console.log(`   Адрес: ${address}`);

    // Fetch data
    const [trades, positions, profile] = await Promise.all([
        fetchTrades(address),
        fetchPositions(address),
        fetchProfile(address),
    ]);

    const displayLabel = profile?.username ? `@${profile.username}` : label;
    console.log(`   Профиль: ${profile?.username || 'не найден'}`);
    console.log(`   Сделок: ${trades.length}, Позиций: ${positions.length}`);

    // Filter trades for last 3 months
    const threeMonthsAgo = Date.now() / 1000 - 90 * 24 * 60 * 60;
    const recentTrades = trades.filter((t) => t.timestamp >= threeMonthsAgo);

    // Sort trades
    recentTrades.sort((a, b) => a.timestamp - b.timestamp);

    // Calculate trade stats
    let totalBought = 0;
    let totalSold = 0;
    let buyCount = 0;
    let sellCount = 0;

    const monthlyStats = new Map<string, MonthlyStats>();

    for (const trade of recentTrades) {
        const month = formatMonth(trade.timestamp);

        if (!monthlyStats.has(month)) {
            monthlyStats.set(month, {
                month,
                totalBought: 0,
                totalSold: 0,
                netFlow: 0,
                tradeCount: 0,
                buyCount: 0,
                sellCount: 0,
            });
        }

        const stats = monthlyStats.get(month)!;
        stats.tradeCount++;

        if (trade.side === 'BUY') {
            totalBought += trade.usdcSize;
            buyCount++;
            stats.totalBought += trade.usdcSize;
            stats.buyCount++;
        } else {
            totalSold += trade.usdcSize;
            sellCount++;
            stats.totalSold += trade.usdcSize;
            stats.sellCount++;
        }

        stats.netFlow = stats.totalSold - stats.totalBought;
    }

    // Calculate position stats
    let totalInitialValue = 0;
    let totalCurrentValue = 0;
    let totalUnrealizedPnL = 0;
    let totalRealizedPnL = 0;
    let redeemableCount = 0;
    let redeemableValue = 0;

    const positionsWithPnL: { title: string; outcome: string; pnl: number; roi: number }[] = [];

    for (const pos of positions) {
        totalInitialValue += pos.initialValue || 0;
        totalCurrentValue += pos.currentValue || 0;
        totalUnrealizedPnL += pos.cashPnl || 0;
        totalRealizedPnL += pos.realizedPnl || 0;

        const totalPnl = (pos.cashPnl || 0) + (pos.realizedPnl || 0);
        positionsWithPnL.push({
            title: pos.title || 'Unknown',
            outcome: pos.outcome || '',
            pnl: totalPnl,
            roi: pos.percentPnl || 0,
        });

        if (pos.redeemable && pos.curPrice >= 0.99) {
            redeemableCount++;
            redeemableValue += pos.currentValue || 0;
        }
    }

    // Sort for top winners/losers
    positionsWithPnL.sort((a, b) => b.pnl - a.pnl);
    const topWinners = positionsWithPnL.filter((p) => p.pnl > 0).slice(0, 5);
    const topLosers = positionsWithPnL.filter((p) => p.pnl < 0).slice(-5).reverse();

    const winners = positions.filter((p) => (p.cashPnl || 0) + (p.realizedPnl || 0) > 0);
    const losers = positions.filter((p) => (p.cashPnl || 0) + (p.realizedPnl || 0) < 0);

    // Calculate ROI
    const totalPnL = totalUnrealizedPnL + totalRealizedPnL;
    const capitalDeployed = totalBought || 1;
    const roiPercent = (totalPnL / capitalDeployed) * 100;

    // Time calculations
    const firstTradeDate = recentTrades.length > 0 ? formatDate(recentTrades[0].timestamp) : 'N/A';
    const lastTradeDate =
        recentTrades.length > 0 ? formatDate(recentTrades[recentTrades.length - 1].timestamp) : 'N/A';
    const daysActive =
        recentTrades.length > 1
            ? (recentTrades[recentTrades.length - 1].timestamp - recentTrades[0].timestamp) / 86400
            : 0;
    const monthsActive = Math.max(daysActive / 30, 1);
    const monthlyRoi = roiPercent / monthsActive;

    // Build result
    const result: TraderAnalysis = {
        address,
        label: displayLabel,
        analysisDate: new Date().toISOString(),
        periodMonths: 3,
        trades: {
            total: recentTrades.length,
            buys: buyCount,
            sells: sellCount,
            firstTrade: firstTradeDate,
            lastTrade: lastTradeDate,
            daysActive: Math.round(daysActive),
        },
        volume: {
            totalBought,
            totalSold,
            netFlow: totalSold - totalBought,
        },
        positions: {
            total: positions.length,
            open: positions.filter((p) => p.curPrice > 0.01 && p.curPrice < 0.99).length,
            winners: winners.length,
            losers: losers.length,
            winRate: positions.length > 0 ? (winners.length / positions.length) * 100 : 0,
            initialValue: totalInitialValue,
            currentValue: totalCurrentValue,
        },
        pnl: {
            unrealized: totalUnrealizedPnL,
            realized: totalRealizedPnL,
            total: totalPnL,
            roi: roiPercent,
            monthlyRoi,
            annualizedRoi: monthlyRoi * 12,
        },
        redeemable: {
            count: redeemableCount,
            value: redeemableValue,
        },
        monthlyBreakdown: Array.from(monthlyStats.values()).sort((a, b) => a.month.localeCompare(b.month)),
        topWinners,
        topLosers,
    };

    return result;
};

const generateReport = (analysis: TraderAnalysis): string => {
    let report = '';

    report += `${'═'.repeat(70)}\n`;
    report += `📊 АНАЛИЗ ТРЕЙДЕРА: ${analysis.label}\n`;
    report += `${'═'.repeat(70)}\n\n`;

    report += `Адрес: ${analysis.address}\n`;
    report += `Дата анализа: ${analysis.analysisDate.split('T')[0]}\n`;
    report += `Период: последние ${analysis.periodMonths} месяца\n`;
    report += `Профиль: https://polymarket.com/profile/${analysis.address}\n\n`;

    report += `${'─'.repeat(70)}\n`;
    report += `📈 ТОРГОВАЯ АКТИВНОСТЬ\n`;
    report += `${'─'.repeat(70)}\n`;
    report += `Всего сделок:      ${analysis.trades.total}\n`;
    report += `  - Покупок:       ${analysis.trades.buys}\n`;
    report += `  - Продаж:        ${analysis.trades.sells}\n`;
    report += `Первая сделка:     ${analysis.trades.firstTrade}\n`;
    report += `Последняя сделка:  ${analysis.trades.lastTrade}\n`;
    report += `Дней активности:   ${analysis.trades.daysActive}\n\n`;

    report += `${'─'.repeat(70)}\n`;
    report += `💰 ОБЪЁМЫ\n`;
    report += `${'─'.repeat(70)}\n`;
    report += `Всего куплено:     $${analysis.volume.totalBought.toFixed(2)}\n`;
    report += `Всего продано:     $${analysis.volume.totalSold.toFixed(2)}\n`;
    report += `Нетто поток:       $${analysis.volume.netFlow.toFixed(2)}\n\n`;

    report += `${'─'.repeat(70)}\n`;
    report += `📊 ПОЗИЦИИ\n`;
    report += `${'─'.repeat(70)}\n`;
    report += `Всего позиций:     ${analysis.positions.total}\n`;
    report += `Открытых:          ${analysis.positions.open}\n`;
    report += `Прибыльных:        ${analysis.positions.winners} (${analysis.positions.winRate.toFixed(0)}%)\n`;
    report += `Убыточных:         ${analysis.positions.losers}\n`;
    report += `Нач. стоимость:    $${analysis.positions.initialValue.toFixed(2)}\n`;
    report += `Текущ. стоимость:  $${analysis.positions.currentValue.toFixed(2)}\n\n`;

    report += `${'─'.repeat(70)}\n`;
    report += `💵 ПРИБЫЛЬ/УБЫТОК\n`;
    report += `${'─'.repeat(70)}\n`;
    report += `Нереализованная:   $${analysis.pnl.unrealized.toFixed(2)}\n`;
    report += `Реализованная:     $${analysis.pnl.realized.toFixed(2)}\n`;
    report += `ОБЩИЙ P&L:         $${analysis.pnl.total.toFixed(2)}\n`;
    report += `ROI:               ${analysis.pnl.roi.toFixed(2)}%\n`;
    report += `Месячный ROI:      ${analysis.pnl.monthlyRoi.toFixed(2)}%\n`;
    report += `Годовой ROI:       ${analysis.pnl.annualizedRoi.toFixed(2)}%\n\n`;

    if (analysis.redeemable.count > 0) {
        report += `${'─'.repeat(70)}\n`;
        report += `🎁 К ВЫВОДУ (Redeemable)\n`;
        report += `${'─'.repeat(70)}\n`;
        report += `Позиций:           ${analysis.redeemable.count}\n`;
        report += `Сумма:             $${analysis.redeemable.value.toFixed(2)}\n\n`;
    }

    report += `${'─'.repeat(70)}\n`;
    report += `📅 ПОМЕСЯЧНАЯ РАЗБИВКА\n`;
    report += `${'─'.repeat(70)}\n`;
    report += `Месяц      | Куплено    | Продано    | Баланс     | Сделок\n`;
    report += `${'─'.repeat(70)}\n`;

    for (const m of analysis.monthlyBreakdown) {
        const sign = m.netFlow >= 0 ? '+' : '';
        report += `${m.month}    | $${m.totalBought.toFixed(2).padStart(9)} | $${m.totalSold.toFixed(2).padStart(9)} | ${sign}$${m.netFlow.toFixed(2).padStart(8)} | ${m.tradeCount}\n`;
    }
    report += '\n';

    if (analysis.topWinners.length > 0) {
        report += `${'─'.repeat(70)}\n`;
        report += `✅ ТОП-5 ПРИБЫЛЬНЫХ ПОЗИЦИЙ\n`;
        report += `${'─'.repeat(70)}\n`;
        for (const w of analysis.topWinners) {
            report += `+$${w.pnl.toFixed(2).padStart(8)} | ${w.title.substring(0, 45)} (${w.outcome})\n`;
        }
        report += '\n';
    }

    if (analysis.topLosers.length > 0) {
        report += `${'─'.repeat(70)}\n`;
        report += `❌ ТОП-5 УБЫТОЧНЫХ ПОЗИЦИЙ\n`;
        report += `${'─'.repeat(70)}\n`;
        for (const l of analysis.topLosers) {
            report += `$${l.pnl.toFixed(2).padStart(9)} | ${l.title.substring(0, 45)} (${l.outcome})\n`;
        }
        report += '\n';
    }

    report += `${'═'.repeat(70)}\n`;

    return report;
};

const main = async () => {
    console.log('🔍 АНАЛИЗ ВСЕХ ТРЕЙДЕРОВ');
    console.log('═'.repeat(60));

    // Get traders to analyze
    const myWallet = ENV.PROXY_WALLET;
    const tradersToFollow: string[] = ENV.USER_ADDRESSES;

    const allAddresses: { address: string; label: string }[] = [
        { address: myWallet, label: 'МОЙ КОШЕЛЁК' },
        ...tradersToFollow.map((addr: string, i: number) => ({
            address: addr,
            label: `Trader ${i + 1}`,
        })),
    ];

    console.log(`\nАнализируем ${allAddresses.length} адресов:`);
    allAddresses.forEach((a) => console.log(`  - ${a.label}: ${a.address.slice(0, 10)}...`));

    // Create output directory
    const outputDir = path.join(process.cwd(), 'trader_reports');
    if (!fs.existsSync(outputDir)) {
        fs.mkdirSync(outputDir, { recursive: true });
    }
    console.log(`\n📁 Результаты будут сохранены в: ${outputDir}`);

    // Analyze each trader
    const allAnalyses: TraderAnalysis[] = [];

    for (const { address, label } of allAddresses) {
        try {
            const analysis = await analyzeTrader(address, label);
            allAnalyses.push(analysis);

            // Save individual report
            const report = generateReport(analysis);
            const filename = `${address.slice(0, 10)}_${label.replace(/[^a-zA-Z0-9]/g, '_')}.txt`;
            fs.writeFileSync(path.join(outputDir, filename), report);

            // Save JSON
            const jsonFilename = `${address.slice(0, 10)}_${label.replace(/[^a-zA-Z0-9]/g, '_')}.json`;
            fs.writeFileSync(path.join(outputDir, jsonFilename), JSON.stringify(analysis, null, 2));

            console.log(`   ✅ Сохранено: ${filename}`);
        } catch (error) {
            console.error(`   ❌ Ошибка анализа ${label}: ${error}`);
        }
    }

    // Generate summary report
    console.log('\n' + '═'.repeat(60));
    console.log('📊 СВОДНАЯ ТАБЛИЦА ТРЕЙДЕРОВ');
    console.log('═'.repeat(60));
    console.log(
        '\nТрейдер              | Сделок | Объём      | P&L        | ROI%   | Win%'
    );
    console.log('─'.repeat(80));

    // Sort by ROI
    allAnalyses.sort((a, b) => b.pnl.roi - a.pnl.roi);

    for (const a of allAnalyses) {
        const name = a.label.substring(0, 20).padEnd(20);
        const trades = String(a.trades.total).padStart(6);
        const volume = `$${a.volume.totalBought.toFixed(0)}`.padStart(10);
        const pnl = `$${a.pnl.total.toFixed(2)}`.padStart(10);
        const roi = `${a.pnl.roi.toFixed(1)}%`.padStart(7);
        const winRate = `${a.positions.winRate.toFixed(0)}%`.padStart(5);

        console.log(`${name} | ${trades} | ${volume} | ${pnl} | ${roi} | ${winRate}`);
    }
    console.log('─'.repeat(80));

    // Save summary
    let summaryReport = '📊 СВОДНЫЙ ОТЧЁТ ПО ВСЕМ ТРЕЙДЕРАМ\n';
    summaryReport += `Дата: ${new Date().toISOString().split('T')[0]}\n`;
    summaryReport += `Период: последние 3 месяца\n\n`;

    summaryReport += 'РЕЙТИНГ ПО ROI:\n';
    summaryReport += '═'.repeat(80) + '\n';
    summaryReport += 'Место | Трейдер              | Сделок | Объём      | P&L        | ROI%   | Win%\n';
    summaryReport += '─'.repeat(80) + '\n';

    allAnalyses.forEach((a, i) => {
        const rank = String(i + 1).padStart(5);
        const name = a.label.substring(0, 20).padEnd(20);
        const trades = String(a.trades.total).padStart(6);
        const volume = `$${a.volume.totalBought.toFixed(0)}`.padStart(10);
        const pnl = `$${a.pnl.total.toFixed(2)}`.padStart(10);
        const roi = `${a.pnl.roi.toFixed(1)}%`.padStart(7);
        const winRate = `${a.positions.winRate.toFixed(0)}%`.padStart(5);

        summaryReport += `${rank} | ${name} | ${trades} | ${volume} | ${pnl} | ${roi} | ${winRate}\n`;
    });

    summaryReport += '═'.repeat(80) + '\n';

    fs.writeFileSync(path.join(outputDir, '_SUMMARY.txt'), summaryReport);
    fs.writeFileSync(path.join(outputDir, '_SUMMARY.json'), JSON.stringify(allAnalyses, null, 2));

    console.log(`\n✅ Все отчёты сохранены в: ${outputDir}`);
    console.log('   - Индивидуальные отчёты (.txt и .json)');
    console.log('   - Сводный отчёт (_SUMMARY.txt и _SUMMARY.json)');
};

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error('❌ Ошибка:', error);
        process.exit(1);
    });
