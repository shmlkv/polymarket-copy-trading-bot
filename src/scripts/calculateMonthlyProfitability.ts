import { ENV } from '../config/env';
import fetchData from '../utils/fetchData';

const PROXY_WALLET = ENV.PROXY_WALLET;

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

const formatMonth = (timestamp: number): string => {
    const date = new Date(timestamp * 1000);
    return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}`;
};

const formatDate = (timestamp: number): string => {
    const date = new Date(timestamp * 1000);
    return date.toISOString().split('T')[0];
};

const fetchAllTrades = async (address: string): Promise<Trade[]> => {
    const url = `https://data-api.polymarket.com/activity?user=${address}&type=TRADE&limit=500`;
    const trades = await fetchData(url);
    return Array.isArray(trades) ? trades : [];
};

const fetchPositions = async (address: string): Promise<Position[]> => {
    const url = `https://data-api.polymarket.com/positions?user=${address}`;
    return await fetchData(url);
};

const main = async () => {
    console.log('📊 РАСЧЁТ ПОМЕСЯЧНОЙ ДОХОДНОСТИ');
    console.log('═'.repeat(60));
    console.log(`Кошелёк: ${PROXY_WALLET}\n`);

    // Fetch all trades
    console.log('⏳ Загрузка истории сделок...');
    const trades = await fetchAllTrades(PROXY_WALLET);
    console.log(`✅ Загружено сделок: ${trades.length}\n`);

    if (trades.length === 0) {
        console.log('❌ Нет сделок для анализа');
        return;
    }

    // Fetch current positions
    console.log('⏳ Загрузка текущих позиций...');
    const positions = await fetchPositions(PROXY_WALLET);
    console.log(`✅ Загружено позиций: ${positions.length}\n`);

    // Sort trades by timestamp (oldest first)
    trades.sort((a, b) => a.timestamp - b.timestamp);

    const firstTradeDate = formatDate(trades[0].timestamp);
    const lastTradeDate = formatDate(trades[trades.length - 1].timestamp);

    console.log(`📅 Период торговли: ${firstTradeDate} → ${lastTradeDate}`);
    console.log('═'.repeat(60));

    // Group trades by month
    const monthlyStats = new Map<string, MonthlyStats>();

    for (const trade of trades) {
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
            stats.totalBought += trade.usdcSize;
            stats.buyCount++;
        } else {
            stats.totalSold += trade.usdcSize;
            stats.sellCount++;
        }

        stats.netFlow = stats.totalSold - stats.totalBought;
    }

    // Calculate position values
    let totalInitialValue = 0;
    let totalCurrentValue = 0;
    let totalUnrealizedPnL = 0;
    let totalRealizedPnL = 0;
    let redeemableValue = 0;

    for (const pos of positions) {
        totalInitialValue += pos.initialValue || 0;
        totalCurrentValue += pos.currentValue || 0;
        totalUnrealizedPnL += pos.cashPnl || 0;
        totalRealizedPnL += pos.realizedPnl || 0;

        if (pos.redeemable && pos.curPrice >= 0.99) {
            redeemableValue += pos.currentValue || 0;
        }
    }

    // Calculate totals from trades
    let totalBought = 0;
    let totalSold = 0;

    for (const trade of trades) {
        if (trade.side === 'BUY') {
            totalBought += trade.usdcSize;
        } else {
            totalSold += trade.usdcSize;
        }
    }

    // Total P&L calculation
    const totalPnL = totalUnrealizedPnL + totalRealizedPnL;
    const capitalDeployed = totalBought;
    const roiPercent = capitalDeployed > 0 ? (totalPnL / capitalDeployed) * 100 : 0;

    // Monthly breakdown
    console.log('\n📈 ПОМЕСЯЧНАЯ СТАТИСТИКА');
    console.log('─'.repeat(60));
    console.log(
        'Месяц      │ Куплено   │ Продано   │ Баланс    │ Сделок'
    );
    console.log('─'.repeat(60));

    const sortedMonths = Array.from(monthlyStats.keys()).sort();

    for (const month of sortedMonths) {
        const stats = monthlyStats.get(month)!;
        const balanceSign = stats.netFlow >= 0 ? '+' : '';
        console.log(
            `${month}    │ $${stats.totalBought.toFixed(2).padStart(8)} │ $${stats.totalSold.toFixed(2).padStart(8)} │ ${balanceSign}$${stats.netFlow.toFixed(2).padStart(7)} │ ${stats.tradeCount} (${stats.buyCount}B/${stats.sellCount}S)`
        );
    }

    console.log('─'.repeat(60));

    // Summary
    console.log('\n💰 ОБЩАЯ СТАТИСТИКА');
    console.log('═'.repeat(60));
    console.log(`Всего куплено:              $${totalBought.toFixed(2)}`);
    console.log(`Всего продано:              $${totalSold.toFixed(2)}`);
    console.log(`Нетто поток:                $${(totalSold - totalBought).toFixed(2)}`);
    console.log('─'.repeat(60));
    console.log(`Начальная стоимость:        $${totalInitialValue.toFixed(2)}`);
    console.log(`Текущая стоимость:          $${totalCurrentValue.toFixed(2)}`);
    console.log('─'.repeat(60));
    console.log(`Нереализованная P&L:        $${totalUnrealizedPnL.toFixed(2)}`);
    console.log(`Реализованная P&L:          $${totalRealizedPnL.toFixed(2)}`);
    console.log('─'.repeat(60));
    console.log(`📊 ОБЩИЙ P&L:               $${totalPnL.toFixed(2)}`);
    console.log(`📊 ROI:                     ${roiPercent.toFixed(2)}%`);
    console.log('═'.repeat(60));

    // Redeemable
    if (redeemableValue > 0) {
        console.log(`\n🎁 К выводу (redeemable):   $${redeemableValue.toFixed(2)}`);
    }

    // Monthly ROI calculation
    const months = sortedMonths.length;
    const daysActive =
        (trades[trades.length - 1].timestamp - trades[0].timestamp) / 86400;
    const monthsActive = Math.max(daysActive / 30, 1);
    const monthlyROI = roiPercent / monthsActive;

    console.log('\n📅 ПОМЕСЯЧНАЯ ДОХОДНОСТЬ');
    console.log('═'.repeat(60));
    console.log(`Дней активности:            ${daysActive.toFixed(0)}`);
    console.log(`Месяцев активности:         ${monthsActive.toFixed(1)}`);
    console.log(`Капитал (депозит):          $${totalBought.toFixed(2)}`);
    console.log('─'.repeat(60));
    console.log(`📊 МЕСЯЧНЫЙ ROI:            ${monthlyROI.toFixed(2)}%`);
    console.log(`📊 ГОДОВОЙ ROI (прогноз):   ${(monthlyROI * 12).toFixed(2)}%`);
    console.log('═'.repeat(60));

    // Position breakdown
    const winners = positions.filter((p) => (p.cashPnl || 0) + (p.realizedPnl || 0) > 0);
    const losers = positions.filter((p) => (p.cashPnl || 0) + (p.realizedPnl || 0) < 0);

    console.log('\n📈 СТАТИСТИКА ПОЗИЦИЙ');
    console.log('─'.repeat(60));
    console.log(`Всего позиций:              ${positions.length}`);
    console.log(`Прибыльных:                 ${winners.length} (${((winners.length / positions.length) * 100).toFixed(0)}%)`);
    console.log(`Убыточных:                  ${losers.length} (${((losers.length / positions.length) * 100).toFixed(0)}%)`);
    console.log('═'.repeat(60));
};

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error('❌ Ошибка:', error);
        process.exit(1);
    });
