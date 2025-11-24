import { ENV } from '../config/env';
import fetchData from '../utils/fetchData';

const PROXY_WALLET = ENV.PROXY_WALLET;

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
    title?: string;
    slug?: string;
    outcome?: string;
}

async function checkPositions() {
    console.log('\n📊 ТЕКУЩИЕ ПОЗИЦИИ:\n');

    const positions: Position[] = await fetchData(
        `https://data-api.polymarket.com/positions?user=${PROXY_WALLET}`
    );

    if (!positions || positions.length === 0) {
        console.log('❌ Нет открытых позиций');
        return;
    }

    console.log(`✅ Найдено позиций: ${positions.length}\n`);

    // Сортируем по текущей стоимости
    const sorted = positions.sort((a, b) => b.currentValue - a.currentValue);

    let totalValue = 0;

    for (const pos of sorted) {
        totalValue += pos.currentValue;

        console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
        console.log(`Market: ${pos.title || 'Unknown'}`);
        console.log(`Outcome: ${pos.outcome || 'Unknown'}`);
        console.log(`Asset ID: ${pos.asset.slice(0, 10)}...`);
        console.log(`Size: ${pos.size.toFixed(2)} shares`);
        console.log(`Avg Price: $${pos.avgPrice.toFixed(4)}`);
        console.log(`Current Price: $${pos.curPrice.toFixed(4)}`);
        console.log(`Initial Value: $${pos.initialValue.toFixed(2)}`);
        console.log(`Current Value: $${pos.currentValue.toFixed(2)}`);
        console.log(`PnL: $${pos.cashPnl.toFixed(2)} (${pos.percentPnl.toFixed(2)}%)`);
        if (pos.slug) console.log(`URL: https://polymarket.com/event/${pos.slug}`);
    }

    console.log(`\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
    console.log(`💰 ОБЩАЯ ТЕКУЩАЯ СТОИМОСТЬ: $${totalValue.toFixed(2)}`);
    console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n`);

    // Определяем большие позиции (больше $5)
    const largePositions = sorted.filter((p) => p.currentValue > 5);

    if (largePositions.length > 0) {
        console.log(`\n🎯 БОЛЬШИЕ ПОЗИЦИИ (> $5): ${largePositions.length}\n`);
        for (const pos of largePositions) {
            console.log(
                `• ${pos.title || 'Unknown'} [${pos.outcome}]: $${pos.currentValue.toFixed(2)} (${pos.size.toFixed(2)} shares @ $${pos.curPrice.toFixed(4)})`
            );
        }

        console.log(`\n💡 Чтобы продать 80% этих позиций, используйте:\n`);
        console.log(`   npm run manual-sell\n`);

        console.log(`📋 Данные для продажи:\n`);
        for (const pos of largePositions) {
            const sellSize = Math.floor(pos.size * 0.8);
            console.log(`   Asset ID: ${pos.asset}`);
            console.log(`   Size to sell: ${sellSize} (80% of ${pos.size.toFixed(2)})`);
            console.log(`   Market: ${pos.title} [${pos.outcome}]`);
            console.log(``);
        }
    } else {
        console.log('\n✅ Нет больших позиций (> $5)');
    }
}

checkPositions().catch(console.error);
