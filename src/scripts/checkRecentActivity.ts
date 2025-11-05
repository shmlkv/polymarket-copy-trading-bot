import fetchData from '../utils/fetchData';
import { ENV } from '../config/env';

const WALLET = ENV.PROXY_WALLET;

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
    market?: string;
}

const main = async () => {
    const url = `https://data-api.polymarket.com/activity?user=${WALLET}&type=TRADE`;
    const activities: Activity[] = await fetchData(url);

    if (!Array.isArray(activities) || activities.length === 0) {
        console.log('Нет данных о сделках');
        return;
    }

    // Redemption закончилось в 18:14:16 UTC (31 октября 2025)
    const redemptionEndTime = new Date('2025-10-31T18:14:16Z').getTime() / 1000;

    console.log('═══════════════════════════════════════════════════════════════');
    console.log('📋 ЗАКРЫТЫЕ ПОЗИЦИИ (Погашено 31 октября 2025 в 18:00-18:14)');
    console.log('═══════════════════════════════════════════════════════════════\n');
    console.log('💰 ВСЕГО ПОЛУЧЕНО ОТ ПОГАШЕНИЯ: $66.37 USDC\n');

    console.log('═══════════════════════════════════════════════════════════════');
    console.log('🛒 ПОКУПКИ ПОСЛЕ ПОГАШЕНИЯ (после 18:14 UTC 31 октября)');
    console.log('═══════════════════════════════════════════════════════════════\n');

    const tradesAfterRedemption = activities.filter((t) => t.timestamp > redemptionEndTime && t.side === 'BUY');

    if (tradesAfterRedemption.length === 0) {
        console.log('✅ Покупок после погашения не было!\n');
        console.log('Значит, средства должны быть на балансе.');
        return;
    }

    let totalSpent = 0;

    tradesAfterRedemption.forEach((trade, i) => {
        const date = new Date(trade.timestamp * 1000);
        const value = trade.usdcSize;
        totalSpent += value;

        console.log(`${i + 1}. 🟢 КУПИЛ: ${trade.title || trade.market || 'Unknown'}`);
        console.log(`   💸 Потрачено: $${value.toFixed(2)}`);
        console.log(`   📊 Размер: ${trade.size.toFixed(2)} токенов @ $${trade.price.toFixed(4)}`);
        console.log(`   📅 Дата: ${date.toLocaleString('ru-RU')}`);
        console.log(
            `   🔗 TX: https://polygonscan.com/tx/${trade.transactionHash.substring(0, 20)}...\n`
        );
    });

    console.log('═══════════════════════════════════════════════════════════════');
    console.log('📊 ИТОГО ПОКУПОК ПОСЛЕ ПОГАШЕНИЯ:');
    console.log(`   Количество сделок: ${tradesAfterRedemption.length}`);
    console.log(`   💸 ПОТРАЧЕНО: $${totalSpent.toFixed(2)} USDC`);
    console.log('═══════════════════════════════════════════════════════════════\n');

    console.log('💡 ОБЪЯСНЕНИЕ КУДА УШЛИ ДЕНЬГИ:\n');
    console.log(`   ✅ Получено от погашения: +$66.37`);
    console.log(`   ❌ Потрачено на новые покупки: -$${totalSpent.toFixed(2)}`);
    console.log(`   📊 Изменение баланса: $${(66.37 - totalSpent).toFixed(2)}`);
    console.log('\n═══════════════════════════════════════════════════════════════\n');

    // Показываем последние продажи тоже
    console.log('💵 ПОСЛЕДНИЕ ПРОДАЖИ:\n');
    const recentSells = activities.filter((t) => t.side === 'SELL').slice(0, 10);

    let totalSold = 0;
    recentSells.forEach((trade, i) => {
        const date = new Date(trade.timestamp * 1000);
        const value = trade.usdcSize;
        totalSold += value;

        console.log(`${i + 1}. 🔴 ПРОДАЛ: ${trade.title || trade.market || 'Unknown'}`);
        console.log(`   💰 Получено: $${value.toFixed(2)}`);
        console.log(`   📅 Дата: ${date.toLocaleString('ru-RU')}\n`);
    });

    console.log('═══════════════════════════════════════════════════════════════');
    console.log(`💵 Продано за последние сделки: $${totalSold.toFixed(2)}`);
    console.log('═══════════════════════════════════════════════════════════════');
};

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error('❌ Error:', error);
        process.exit(1);
    });
