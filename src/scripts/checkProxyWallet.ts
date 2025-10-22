import { ethers } from 'ethers';
import { ENV } from '../config/env';
import fetchData from '../utils/fetchData';

const PROXY_WALLET = ENV.PROXY_WALLET;
const PRIVATE_KEY = ENV.PRIVATE_KEY;
const RPC_URL = ENV.RPC_URL;

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
}

const checkProxyWallet = async () => {
  console.log('🔍 ПРОВЕРКА PROXY WALLET И ОСНОВНОГО КОШЕЛЬКА\n');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

  try {
    // 1. Получаем EOA (основной кошелек) из приватного ключа
    const wallet = new ethers.Wallet(PRIVATE_KEY);
    const eoaAddress = wallet.address;

    console.log('📍 ВАШИ АДРЕСА:\n');
    console.log(`   EOA (Основной кошелек):  ${eoaAddress}`);
    console.log(`   Proxy Wallet (Контракт): ${PROXY_WALLET}\n`);

    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

    // 2. Проверяем активность на EOA
    console.log('🔎 ПРОВЕРКА АКТИВНОСТИ НА ОСНОВНОМ КОШЕЛЬКЕ (EOA):\n');
    const eoaActivityUrl = `https://data-api.polymarket.com/activity?user=${eoaAddress}&type=TRADE`;
    const eoaActivities: Activity[] = await fetchData(eoaActivityUrl);

    console.log(`   Адрес: ${eoaAddress}`);
    console.log(`   Сделок: ${eoaActivities?.length || 0}`);
    console.log(`   Профиль: https://polymarket.com/profile/${eoaAddress}\n`);

    if (eoaActivities && eoaActivities.length > 0) {
      const buyTrades = eoaActivities.filter(a => a.side === 'BUY');
      const sellTrades = eoaActivities.filter(a => a.side === 'SELL');
      const totalBuyVolume = buyTrades.reduce((sum, t) => sum + t.usdcSize, 0);
      const totalSellVolume = sellTrades.reduce((sum, t) => sum + t.usdcSize, 0);

      console.log('   📊 Статистика EOA:');
      console.log(`      • Покупок: ${buyTrades.length} ($${totalBuyVolume.toFixed(2)})`);
      console.log(`      • Продаж: ${sellTrades.length} ($${totalSellVolume.toFixed(2)})`);
      console.log(`      • Объем: $${(totalBuyVolume + totalSellVolume).toFixed(2)}\n`);

      // Показываем последние 3 сделки
      console.log('   📝 Последние 3 сделки:');
      eoaActivities.slice(0, 3).forEach((trade, idx) => {
        const date = new Date(trade.timestamp * 1000);
        console.log(`      ${idx + 1}. ${trade.side} - ${trade.title || 'Unknown'}`);
        console.log(`         $${trade.usdcSize.toFixed(2)} @ ${date.toLocaleDateString()}`);
      });
      console.log('');
    } else {
      console.log('   ❌ Сделок не найдено на основном кошельке\n');
    }

    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

    // 3. Проверяем активность на Proxy Wallet
    console.log('🔎 ПРОВЕРКА АКТИВНОСТИ НА PROXY WALLET (КОНТРАКТ):\n');
    const proxyActivityUrl = `https://data-api.polymarket.com/activity?user=${PROXY_WALLET}&type=TRADE`;
    const proxyActivities: Activity[] = await fetchData(proxyActivityUrl);

    console.log(`   Адрес: ${PROXY_WALLET}`);
    console.log(`   Сделок: ${proxyActivities?.length || 0}`);
    console.log(`   Профиль: https://polymarket.com/profile/${PROXY_WALLET}\n`);

    if (proxyActivities && proxyActivities.length > 0) {
      const buyTrades = proxyActivities.filter(a => a.side === 'BUY');
      const sellTrades = proxyActivities.filter(a => a.side === 'SELL');
      const totalBuyVolume = buyTrades.reduce((sum, t) => sum + t.usdcSize, 0);
      const totalSellVolume = sellTrades.reduce((sum, t) => sum + t.usdcSize, 0);

      console.log('   📊 Статистика Proxy Wallet:');
      console.log(`      • Покупок: ${buyTrades.length} ($${totalBuyVolume.toFixed(2)})`);
      console.log(`      • Продаж: ${sellTrades.length} ($${totalSellVolume.toFixed(2)})`);
      console.log(`      • Объем: $${(totalBuyVolume + totalSellVolume).toFixed(2)}\n`);

      // Показываем последние 3 сделки
      console.log('   📝 Последние 3 сделки:');
      proxyActivities.slice(0, 3).forEach((trade, idx) => {
        const date = new Date(trade.timestamp * 1000);
        console.log(`      ${idx + 1}. ${trade.side} - ${trade.title || 'Unknown'}`);
        console.log(`         $${trade.usdcSize.toFixed(2)} @ ${date.toLocaleDateString()}`);
      });
      console.log('');
    } else {
      console.log('   ❌ Сделок не найдено на proxy wallet\n');
    }

    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

    // 4. Проверяем связь между адресами
    console.log('🔗 СВЯЗЬ МЕЖДУ АДРЕСАМИ:\n');

    // Проверяем, есть ли поле proxyWallet в сделках
    if (eoaActivities && eoaActivities.length > 0) {
      const sampleTrade = eoaActivities[0];
      console.log(`   EOA сделки содержат proxyWallet: ${sampleTrade.proxyWallet || 'N/A'}`);
    }

    if (proxyActivities && proxyActivities.length > 0) {
      const sampleTrade = proxyActivities[0];
      console.log(`   Proxy сделки содержат proxyWallet: ${sampleTrade.proxyWallet || 'N/A'}`);
    }

    console.log('\n   💡 КАК ЭТО РАБОТАЕТ:\n');
    console.log('   1. EOA (Externally Owned Account) - ваш основной кошелек');
    console.log('      • Контролируется приватным ключом');
    console.log('      • Подписывает транзакции');
    console.log('      • НЕ хранит средства на Polymarket\n');

    console.log('   2. Proxy Wallet - смарт-контракт кошелек');
    console.log('      • Создается Polymarket автоматически');
    console.log('      • Хранит USDC и токены позиций');
    console.log('      • Выполняет сделки от имени EOA');
    console.log('      • Связан с EOA через подпись\n');

    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

    // 5. Определяем проблему
    console.log('❓ ПОЧЕМУ НЕТ СТАТИСТИКИ НА ПРОФИЛЕ?\n');

    const eoaHasTrades = eoaActivities && eoaActivities.length > 0;
    const proxyHasTrades = proxyActivities && proxyActivities.length > 0;

    if (!eoaHasTrades && proxyHasTrades) {
      console.log('   🎯 НАЙДЕНА ПРОБЛЕМА!\n');
      console.log('   Все сделки идут через Proxy Wallet, но статистика на Polymarket');
      console.log('   может отображаться на профиле основного кошелька (EOA).\n');

      console.log('   📊 ГДЕ СМОТРЕТЬ СТАТИСТИКУ:\n');
      console.log(`   ✅ ПРАВИЛЬНЫЙ профиль (с торговлей):`);
      console.log(`      https://polymarket.com/profile/${PROXY_WALLET}\n`);

      console.log(`   ❌ Профиль EOA (может быть пустым):`);
      console.log(`      https://polymarket.com/profile/${eoaAddress}\n`);

      console.log('   💡 РЕШЕНИЕ:\n');
      console.log('   Используйте адрес Proxy Wallet для просмотра статистики:');
      console.log(`   ${PROXY_WALLET}\n`);

    } else if (eoaHasTrades && !proxyHasTrades) {
      console.log('   Сделки идут через основной кошелек (EOA)');
      console.log('   Статистика должна отображаться на профиле EOA\n');
    } else if (eoaHasTrades && proxyHasTrades) {
      console.log('   Сделки есть на обоих адресах!');
      console.log('   Возможно, вы использовали разные кошельки\n');
    } else {
      console.log('   ❌ Сделок не найдено ни на одном адресе\n');
    }

    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

    // 6. Проверяем через blockchain
    console.log('🔗 ПРОВЕРКА В БЛОКЧЕЙНЕ:\n');
    console.log(`   EOA (основной):`);
    console.log(`   https://polygonscan.com/address/${eoaAddress}\n`);
    console.log(`   Proxy Wallet (контракт):`);
    console.log(`   https://polygonscan.com/address/${PROXY_WALLET}\n`);

    // Проверяем тип адреса через RPC
    try {
      const provider = new ethers.providers.JsonRpcProvider(RPC_URL);

      const eoaCode = await provider.getCode(eoaAddress);
      const proxyCode = await provider.getCode(PROXY_WALLET);

      console.log('   🔍 Тип адресов:');
      console.log(`      EOA: ${eoaCode === '0x' ? '✅ Обычный кошелек (EOA)' : '⚠️  Смарт-контракт'}`);
      console.log(`      Proxy: ${proxyCode === '0x' ? '❌ Обычный кошелек (ошибка!)' : '✅ Смарт-контракт (правильно)'}\n`);
    } catch (error) {
      console.log('   ⚠️  Не удалось проверить тип адресов через RPC\n');
    }

    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

    console.log('✅ ИТОГ:\n');
    console.log('   Ваш бот использует PROXY_WALLET для торговли.');
    console.log('   Это правильно и безопасно!\n');
    console.log('   Статистика и графики должны отображаться на:');
    console.log(`   🔗 https://polymarket.com/profile/${PROXY_WALLET}\n`);
    console.log('   Если там все еще нет графиков, это баг Polymarket UI.\n');

  } catch (error) {
    console.error('❌ Ошибка:', error);
  }
};

checkProxyWallet();

