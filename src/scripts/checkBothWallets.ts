import { ENV } from '../config/env';
import fetchData from '../utils/fetchData';
import getMyBalance from '../utils/getMyBalance';

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
    title?: string;
    slug?: string;
    outcome?: string;
}

const checkBothWallets = async () => {
    console.log('🔍 ПРОВЕРКА ОБОИХ АДРЕСОВ\n');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

    const ADDRESS_1 = '0x4fbBe5599c06e846D2742014c9eB04A8a3d1DE8C'; // Из .env
    const ADDRESS_2 = '0xd62531bc536bff72394fc5ef715525575787e809'; // Из профиля

    try {
        // 1. Проверяем первый адрес (из .env)
        console.log('📊 АДРЕС 1 (из .env - PROXY_WALLET):\n');
        console.log(`   ${ADDRESS_1}`);
        console.log(`   Профиль: https://polymarket.com/profile/${ADDRESS_1}\n`);

        const addr1Activities: Activity[] = await fetchData(
            `https://data-api.polymarket.com/activity?user=${ADDRESS_1}&type=TRADE`
        );
        const addr1Positions: Position[] = await fetchData(
            `https://data-api.polymarket.com/positions?user=${ADDRESS_1}`
        );

        console.log(`   • Сделок в API: ${addr1Activities?.length || 0}`);
        console.log(`   • Позиций в API: ${addr1Positions?.length || 0}`);

        if (addr1Activities && addr1Activities.length > 0) {
            const buyTrades = addr1Activities.filter((a) => a.side === 'BUY');
            const sellTrades = addr1Activities.filter((a) => a.side === 'SELL');
            const totalVolume =
                buyTrades.reduce((s, t) => s + t.usdcSize, 0) +
                sellTrades.reduce((s, t) => s + t.usdcSize, 0);

            console.log(`   • Покупок: ${buyTrades.length}`);
            console.log(`   • Продаж: ${sellTrades.length}`);
            console.log(`   • Объем: $${totalVolume.toFixed(2)}`);

            // Показываем proxyWallet из первой сделки
            if (addr1Activities[0]?.proxyWallet) {
                console.log(`   • proxyWallet в сделках: ${addr1Activities[0].proxyWallet}`);
            }
        }

        // Баланс
        try {
            const balance1 = await getMyBalance(ADDRESS_1);
            console.log(`   • Баланс USDC: $${balance1.toFixed(2)}`);
        } catch (e) {
            console.log('   • Баланс USDC: не удалось получить');
        }

        console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

        // 2. Проверяем второй адрес (из профиля @shbot)
        console.log('📊 АДРЕС 2 (из профиля @shbot):\n');
        console.log(`   ${ADDRESS_2}`);
        console.log(`   Профиль: https://polymarket.com/profile/${ADDRESS_2}\n`);

        const addr2Activities: Activity[] = await fetchData(
            `https://data-api.polymarket.com/activity?user=${ADDRESS_2}&type=TRADE`
        );
        const addr2Positions: Position[] = await fetchData(
            `https://data-api.polymarket.com/positions?user=${ADDRESS_2}`
        );

        console.log(`   • Сделок в API: ${addr2Activities?.length || 0}`);
        console.log(`   • Позиций в API: ${addr2Positions?.length || 0}`);

        if (addr2Activities && addr2Activities.length > 0) {
            const buyTrades = addr2Activities.filter((a) => a.side === 'BUY');
            const sellTrades = addr2Activities.filter((a) => a.side === 'SELL');
            const totalVolume =
                buyTrades.reduce((s, t) => s + t.usdcSize, 0) +
                sellTrades.reduce((s, t) => s + t.usdcSize, 0);

            console.log(`   • Покупок: ${buyTrades.length}`);
            console.log(`   • Продаж: ${sellTrades.length}`);
            console.log(`   • Объем: $${totalVolume.toFixed(2)}`);

            // Показываем proxyWallet из первой сделки
            if (addr2Activities[0]?.proxyWallet) {
                console.log(`   • proxyWallet в сделках: ${addr2Activities[0].proxyWallet}`);
            }

            // Последние 5 сделок для сравнения
            console.log('\n   📝 Последние 5 сделок:');
            addr2Activities.slice(0, 5).forEach((trade, idx) => {
                const date = new Date(trade.timestamp * 1000);
                console.log(`      ${idx + 1}. ${trade.side} - ${trade.title || 'Unknown'}`);
                console.log(
                    `         $${trade.usdcSize.toFixed(2)} @ ${date.toLocaleString('ru-RU')}`
                );
                console.log(
                    `         TX: ${trade.transactionHash.slice(0, 10)}...${trade.transactionHash.slice(-6)}`
                );
            });
        }

        // Баланс
        try {
            const balance2 = await getMyBalance(ADDRESS_2);
            console.log(`\n   • Баланс USDC: $${balance2.toFixed(2)}`);
        } catch (e) {
            console.log('\n   • Баланс USDC: не удалось получить');
        }

        console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

        // 3. Сравнение
        console.log('🔍 СРАВНЕНИЕ АДРЕСОВ:\n');

        const addr1HasData =
            (addr1Activities?.length || 0) > 0 || (addr1Positions?.length || 0) > 0;
        const addr2HasData =
            (addr2Activities?.length || 0) > 0 || (addr2Positions?.length || 0) > 0;

        console.log(`   Адрес 1 (${ADDRESS_1.slice(0, 8)}...):`);
        console.log(`   ${addr1HasData ? '✅ Есть данные' : '❌ Нет данных'}`);
        console.log(`   • Сделок: ${addr1Activities?.length || 0}`);
        console.log(`   • Позиций: ${addr1Positions?.length || 0}\n`);

        console.log(`   Адрес 2 (${ADDRESS_2.slice(0, 8)}...):`);
        console.log(`   ${addr2HasData ? '✅ Есть данные' : '❌ Нет данных'}`);
        console.log(`   • Сделок: ${addr2Activities?.length || 0}`);
        console.log(`   • Позиций: ${addr2Positions?.length || 0}\n`);

        // 4. Проверяем связь через proxyWallet поле
        console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
        console.log('🔗 СВЯЗЬ МЕЖДУ АДРЕСАМИ:\n');

        if (addr1Activities?.[0]?.proxyWallet && addr2Activities?.[0]?.proxyWallet) {
            const proxy1 = addr1Activities[0].proxyWallet.toLowerCase();
            const proxy2 = addr2Activities[0].proxyWallet.toLowerCase();

            console.log(`   Адрес 1 использует proxyWallet: ${proxy1}`);
            console.log(`   Адрес 2 использует proxyWallet: ${proxy2}\n`);

            if (proxy1 === proxy2) {
                console.log('   ✅ ОБА АДРЕСА СВЯЗАНЫ С ОДНИМ PROXY WALLET!\n');
                console.log('   Это объясняет, почему профили показывают одинаковые данные.\n');
            } else if (proxy1 === ADDRESS_2.toLowerCase()) {
                console.log('   🎯 НАЙДЕНА СВЯЗЬ!\n');
                console.log(`   Адрес 1 (${ADDRESS_1.slice(0, 8)}...) использует`);
                console.log(`   Адрес 2 (${ADDRESS_2.slice(0, 8)}...) как proxy wallet!\n`);
            } else if (proxy2 === ADDRESS_1.toLowerCase()) {
                console.log('   🎯 НАЙДЕНА СВЯЗЬ!\n');
                console.log(`   Адрес 2 (${ADDRESS_2.slice(0, 8)}...) использует`);
                console.log(`   Адрес 1 (${ADDRESS_1.slice(0, 8)}...) как proxy wallet!\n`);
            } else {
                console.log('   ⚠️  Адреса используют разные proxy wallets\n');
            }
        }

        // 5. Проверяем через Polymarket username API
        console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
        console.log('👤 ПРОФИЛЬ @shbot:\n');

        console.log('   Варианты URL профиля:');
        console.log(`   • https://polymarket.com/@shbot`);
        console.log(`   • https://polymarket.com/profile/${ADDRESS_1}`);
        console.log(`   • https://polymarket.com/profile/${ADDRESS_2}\n`);

        console.log('   💡 Polymarket может связывать несколько адресов с одним профилем:');
        console.log('   • Основной адрес (EOA) - для входа');
        console.log('   • Proxy адрес - для торговли');
        console.log('   • Username (@shbot) - для публичного профиля\n');

        console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

        // 6. Итоговое решение
        console.log('✅ ИТОГ И РЕШЕНИЕ:\n');

        if (addr2HasData && !addr1HasData) {
            console.log('   🎯 ВАШ БОТ ИСПОЛЬЗУЕТ НЕПРАВИЛЬНЫЙ АДРЕС!\n');
            console.log('   Вся торговля идет через адрес:');
            console.log(`   ${ADDRESS_2}\n`);
            console.log('   Но в .env указан:');
            console.log(`   ${ADDRESS_1}\n`);
            console.log('   🔧 РЕШЕНИЕ: Обновите .env файл:\n');
            console.log(`   PROXY_WALLET=${ADDRESS_2}\n`);
        } else if (addr1HasData && !addr2HasData) {
            console.log('   ✅ Бот работает правильно!');
            console.log('   Торговля идет через адрес из .env\n');
            console.log('   Но профиль @shbot может быть привязан к другому адресу.');
            console.log('   Это нормально, если вы недавно переключили кошельки.\n');
        } else if (addr1HasData && addr2HasData) {
            console.log('   ⚠️  Активность на ОБОИХ адресах!\n');
            console.log('   Возможные причины:');
            console.log('   1. Вы переключали кошельки');
            console.log('   2. Торговали вручную с одного, ботом с другого');
            console.log('   3. Оба адреса связаны через proxy систему Polymarket\n');

            // Сравниваем последние сделки
            if (addr1Activities?.[0] && addr2Activities?.[0]) {
                const lastTrade1 = new Date(addr1Activities[0].timestamp * 1000);
                const lastTrade2 = new Date(addr2Activities[0].timestamp * 1000);

                console.log('   Последняя сделка:');
                console.log(`   • Адрес 1: ${lastTrade1.toLocaleString('ru-RU')}`);
                console.log(`   • Адрес 2: ${lastTrade2.toLocaleString('ru-RU')}\n`);

                if (Math.abs(lastTrade1.getTime() - lastTrade2.getTime()) < 60000) {
                    console.log('   ✅ Сделки синхронизированы (< 1 минуты разницы)');
                    console.log('   Скорее всего, это один и тот же аккаунт!\n');
                }
            }
        } else {
            console.log('   ❌ Нет данных ни на одном адресе!\n');
            console.log('   Проверьте правильность адресов.\n');
        }

        console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
    } catch (error) {
        console.error('❌ Ошибка:', error);
    }
};

checkBothWallets();
