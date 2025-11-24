import { ENV } from '../config/env';
import fetchData from '../utils/fetchData';

const PROXY_WALLET = ENV.PROXY_WALLET;

interface Activity {
    proxyWallet: string;
    timestamp: number;
    conditionId: string;
    type: string;
    size: number;
    usdcSize: number;
    transactionHash: string;
    price: number;
    asset: string;
    side: 'BUY' | 'SELL';
    title?: string;
    slug?: string;
    outcome?: string;
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
    totalBought: number;
    realizedPnl: number;
    percentRealizedPnl: number;
    curPrice: number;
    redeemable: boolean;
    title?: string;
    slug?: string;
    outcome?: string;
}

const checkDiscrepancy = async () => {
    console.log('🔍 Детальная проверка расхождений P&L\n');
    console.log(`Кошелек: ${PROXY_WALLET}\n`);
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

    try {
        // 1. Получаем все позиции (открытые и закрытые)
        console.log('📊 Получение данных из Polymarket API...\n');

        const positionsUrl = `https://data-api.polymarket.com/positions?user=${PROXY_WALLET}`;
        const positions: Position[] = await fetchData(positionsUrl);

        console.log(`Получено позиций: ${positions.length}\n`);

        // 2. Разделяем на открытые и закрытые
        const openPositions = positions.filter((p) => p.size > 0);
        const closedPositions = positions.filter((p) => p.size === 0);

        console.log(`• Открытые: ${openPositions.length}`);
        console.log(`• Закрытые: ${closedPositions.length}\n`);

        console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

        // 3. Анализ ОТКРЫТЫХ позиций
        console.log('📈 ОТКРЫТЫЕ ПОЗИЦИИ:\n');
        let totalOpenValue = 0;
        let totalOpenInitial = 0;
        let totalUnrealizedPnl = 0;
        let totalOpenRealized = 0;

        openPositions.forEach((pos, idx) => {
            totalOpenValue += pos.currentValue || 0;
            totalOpenInitial += pos.initialValue || 0;
            totalUnrealizedPnl += pos.cashPnl || 0;
            totalOpenRealized += pos.realizedPnl || 0;

            console.log(`${idx + 1}. ${pos.title || 'Unknown'} - ${pos.outcome || 'N/A'}`);
            console.log(`   Size: ${pos.size.toFixed(2)} @ $${pos.avgPrice.toFixed(3)}`);
            console.log(`   Current Value: $${pos.currentValue.toFixed(2)}`);
            console.log(`   Initial Value: $${pos.initialValue.toFixed(2)}`);
            console.log(
                `   Unrealized P&L: $${(pos.cashPnl || 0).toFixed(2)} (${(pos.percentPnl || 0).toFixed(2)}%)`
            );
            console.log(`   Realized P&L: $${(pos.realizedPnl || 0).toFixed(2)}`);
            console.log('');
        });

        console.log(`   ИТОГО по открытым:`);
        console.log(`   • Текущая стоимость: $${totalOpenValue.toFixed(2)}`);
        console.log(`   • Начальная стоимость: $${totalOpenInitial.toFixed(2)}`);
        console.log(`   • Нереализованная прибыль: $${totalUnrealizedPnl.toFixed(2)}`);
        console.log(`   • Реализованная прибыль: $${totalOpenRealized.toFixed(2)}\n`);

        console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

        // 4. Анализ ЗАКРЫТЫХ позиций
        console.log('✅ ЗАКРЫТЫЕ ПОЗИЦИИ:\n');
        let totalClosedRealized = 0;
        let totalClosedInitial = 0;

        if (closedPositions.length > 0) {
            closedPositions.forEach((pos, idx) => {
                totalClosedRealized += pos.realizedPnl || 0;
                totalClosedInitial += pos.initialValue || 0;

                console.log(`${idx + 1}. ${pos.title || 'Unknown'} - ${pos.outcome || 'N/A'}`);
                console.log(`   Initial Value: $${pos.initialValue.toFixed(2)}`);
                console.log(`   Realized P&L: $${(pos.realizedPnl || 0).toFixed(2)}`);
                console.log(`   % P&L: ${(pos.percentRealizedPnl || 0).toFixed(2)}%`);
                console.log('');
            });

            console.log(`   ИТОГО по закрытым:`);
            console.log(`   • Начальные инвестиции: $${totalClosedInitial.toFixed(2)}`);
            console.log(`   • Реализованная прибыль: $${totalClosedRealized.toFixed(2)}\n`);
        } else {
            console.log('   ❌ Закрытых позиций не найдено в API\n');
        }

        console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

        // 5. ОБЩАЯ статистика
        console.log('📊 ОБЩАЯ СТАТИСТИКА:\n');
        const totalRealized = totalOpenRealized + totalClosedRealized;

        console.log(`   • Открытые позиции - Реализованная P&L: $${totalOpenRealized.toFixed(2)}`);
        console.log(
            `   • Закрытые позиции - Реализованная P&L: $${totalClosedRealized.toFixed(2)}`
        );
        console.log(`   • Нереализованная P&L: $${totalUnrealizedPnl.toFixed(2)}`);
        console.log(`   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
        console.log(`   💰 ВСЕГО РЕАЛИЗОВАННОЙ ПРИБЫЛИ: $${totalRealized.toFixed(2)}\n`);

        console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

        // 6. Проверка через историю сделок
        console.log('🔎 ПРОВЕРКА ЧЕРЕЗ ИСТОРИЮ СДЕЛОК:\n');
        const activityUrl = `https://data-api.polymarket.com/activity?user=${PROXY_WALLET}&type=TRADE`;
        const activities: Activity[] = await fetchData(activityUrl);

        // Группируем сделки по рынкам
        const marketTrades = new Map<string, { buys: Activity[]; sells: Activity[] }>();

        activities.forEach((trade) => {
            const key = `${trade.conditionId}:${trade.asset}`;
            if (!marketTrades.has(key)) {
                marketTrades.set(key, { buys: [], sells: [] });
            }
            const group = marketTrades.get(key)!;
            if (trade.side === 'BUY') {
                group.buys.push(trade);
            } else {
                group.sells.push(trade);
            }
        });

        console.log(`   Найдено рынков с активностью: ${marketTrades.size}\n`);

        // Вычисляем реализованную прибыль по сделкам
        let calculatedRealizedPnl = 0;
        let marketsWithProfit = 0;

        for (const [key, trades] of marketTrades.entries()) {
            const totalBought = trades.buys.reduce((sum, t) => sum + t.usdcSize, 0);
            const totalSold = trades.sells.reduce((sum, t) => sum + t.usdcSize, 0);
            const pnl = totalSold - totalBought;

            if (Math.abs(pnl) > 0.01) {
                const market = trades.buys[0] || trades.sells[0];
                console.log(`   ${market.title || 'Unknown'}`);
                console.log(`   • Куплено: $${totalBought.toFixed(2)}`);
                console.log(`   • Продано: $${totalSold.toFixed(2)}`);
                console.log(`   • P&L: $${pnl.toFixed(2)}`);
                console.log('');

                if (totalSold > 0) {
                    calculatedRealizedPnl += pnl;
                    marketsWithProfit++;
                }
            }
        }

        console.log(
            `   💰 Вычисленная реализованная прибыль: $${calculatedRealizedPnl.toFixed(2)}`
        );
        console.log(`   📊 Рынков с закрытой прибылью: ${marketsWithProfit}\n`);

        console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

        // 7. Выводы
        console.log('💡 ВЫВОДЫ:\n');
        console.log(`   1. API возвращает реализованную прибыль: $${totalRealized.toFixed(2)}`);
        console.log(`   2. По истории сделок вычислено: $${calculatedRealizedPnl.toFixed(2)}`);
        console.log(`   3. UI Polymarket показывает: ~$12.02\n`);

        if (Math.abs(totalRealized - calculatedRealizedPnl) > 1) {
            console.log('   ⚠️  ОБНАРУЖЕНО РАСХОЖДЕНИЕ!\n');
            console.log('   Возможные причины:');
            console.log('   • API учитывает только частично закрытые позиции');
            console.log('   • UI включает нереализованные частичные продажи');
            console.log('   • Задержка синхронизации данных между UI и API');
            console.log('   • Разная методология расчета P&L\n');
        }

        console.log('   📈 Почему график показывает $0.00:');
        console.log('   • Сумма слишком мала ($2-12) для визуализации');
        console.log('   • Временная шкала не начинается с $0');
        console.log('   • График требует минимум несколько точек данных');
        console.log('   • Задержка обновления UI (может быть 1-24 часа)\n');

        console.log('   🔧 Рекомендации:');
        console.log('   1. Подождите 24 часа для полного обновления');
        console.log('   2. Закройте больше позиций для увеличения реализованной прибыли');
        console.log('   3. Попробуйте очистить кэш браузера');
        console.log('   4. Проверьте в режиме инкогнито\n');

        console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
    } catch (error) {
        console.error('❌ Ошибка:', error);
    }
};

checkDiscrepancy();
