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

const checkMyStats = async () => {
  console.log('🔍 Проверка статистики вашего кошелька на Polymarket\n');
  console.log(`Кошелек: ${PROXY_WALLET}\n`);
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

  try {
    // 1. Баланс USDC
    console.log('💰 БАЛАНС USDC');
    const balance = await getMyBalance(PROXY_WALLET);
    console.log(`   Доступно: $${balance.toFixed(2)}\n`);

    // 2. Открытые позиции
    console.log('📊 ОТКРЫТЫЕ ПОЗИЦИИ');
    const positionsUrl = `https://data-api.polymarket.com/positions?user=${PROXY_WALLET}`;
    const positions: Position[] = await fetchData(positionsUrl);

    if (positions && positions.length > 0) {
      console.log(`   Всего позиций: ${positions.length}\n`);

      let totalValue = 0;
      let totalInitialValue = 0;
      let totalUnrealizedPnl = 0;
      let totalRealizedPnl = 0;

      positions.forEach((pos) => {
        totalValue += pos.currentValue || 0;
        totalInitialValue += pos.initialValue || 0;
        totalUnrealizedPnl += pos.cashPnl || 0;
        totalRealizedPnl += pos.realizedPnl || 0;
      });

      console.log(`   💵 Текущая стоимость: $${totalValue.toFixed(2)}`);
      console.log(`   💵 Начальная стоимость: $${totalInitialValue.toFixed(2)}`);
      console.log(`   📈 Нереализованная прибыль: $${totalUnrealizedPnl.toFixed(2)} (${((totalUnrealizedPnl / totalInitialValue) * 100).toFixed(2)}%)`);
      console.log(`   ✅ Реализованная прибыль: $${totalRealizedPnl.toFixed(2)}\n`);

      // Топ 5 позиций по прибыли
      console.log('   🏆 Топ-5 позиций по прибыли:\n');
      const topPositions = [...positions]
        .sort((a, b) => (b.percentPnl || 0) - (a.percentPnl || 0))
        .slice(0, 5);

      topPositions.forEach((pos, idx) => {
        const pnlSign = (pos.percentPnl || 0) >= 0 ? '📈' : '📉';
        console.log(`   ${idx + 1}. ${pnlSign} ${pos.title || 'Unknown'}`);
        console.log(`      ${pos.outcome || 'N/A'}`);
        console.log(`      Размер: ${pos.size.toFixed(2)} токенов @ $${pos.avgPrice.toFixed(3)}`);
        console.log(`      P&L: $${(pos.cashPnl || 0).toFixed(2)} (${(pos.percentPnl || 0).toFixed(2)}%)`);
        console.log(`      Текущая цена: $${pos.curPrice.toFixed(3)}`);
        if (pos.slug) {
          console.log(`      📍 https://polymarket.com/event/${pos.slug}`);
        }
        console.log('');
      });
    } else {
      console.log('   ❌ Открытых позиций не найдено\n');
    }

    // 3. История сделок (последние 50)
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
    console.log('📜 ИСТОРИЯ СДЕЛОК (последние 20)\n');
    const activityUrl = `https://data-api.polymarket.com/activity?user=${PROXY_WALLET}&type=TRADE`;
    const activities: Activity[] = await fetchData(activityUrl);

    if (activities && activities.length > 0) {
      console.log(`   Всего сделок в API: ${activities.length}\n`);

      // Статистика по сделкам
      const buyTrades = activities.filter((a) => a.side === 'BUY');
      const sellTrades = activities.filter((a) => a.side === 'SELL');
      const totalBuyVolume = buyTrades.reduce((sum, t) => sum + t.usdcSize, 0);
      const totalSellVolume = sellTrades.reduce((sum, t) => sum + t.usdcSize, 0);

      console.log('   📊 Статистика сделок:');
      console.log(`      • Покупок: ${buyTrades.length} (объем: $${totalBuyVolume.toFixed(2)})`);
      console.log(`      • Продаж: ${sellTrades.length} (объем: $${totalSellVolume.toFixed(2)})`);
      console.log(`      • Всего объем: $${(totalBuyVolume + totalSellVolume).toFixed(2)}\n`);

      // Последние 20 сделок
      const recentTrades = activities.slice(0, 20);
      console.log('   📝 Последние 20 сделок:\n');

      recentTrades.forEach((trade, idx) => {
        const date = new Date(trade.timestamp * 1000);
        const sideIcon = trade.side === 'BUY' ? '🟢' : '🔴';
        console.log(`   ${idx + 1}. ${sideIcon} ${trade.side} - ${date.toLocaleString('ru-RU')}`);
        console.log(`      ${trade.title || 'Unknown Market'}`);
        console.log(`      ${trade.outcome || 'N/A'}`);
        console.log(`      Объем: $${trade.usdcSize.toFixed(2)} @ $${trade.price.toFixed(3)}`);
        console.log(`      TX: ${trade.transactionHash.slice(0, 10)}...${trade.transactionHash.slice(-8)}`);
        console.log(`      🔗 https://polygonscan.com/tx/${trade.transactionHash}`);
        console.log('');
      });
    } else {
      console.log('   ❌ История сделок не найдена\n');
    }

    // 4. Почему нет графиков P&L
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
    console.log('❓ ПОЧЕМУ НЕТ ГРАФИКОВ P&L НА POLYMARKET?\n');
    console.log('   Графики Profit/Loss на Polymarket показывают только РЕАЛИЗОВАННУЮ');
    console.log('   прибыль (закрытые позиции). Вот почему у вас показывает $0.00:\n');

    if (positions && positions.length > 0) {
      const totalRealizedPnl = positions.reduce((sum, p) => sum + (p.realizedPnl || 0), 0);
      const totalUnrealizedPnl = positions.reduce((sum, p) => sum + (p.cashPnl || 0), 0);

      console.log('   ✅ Реализованная прибыль (закрытые позиции):');
      console.log(`      → $${totalRealizedPnl.toFixed(2)} ← ЭТО отображается на графике\n`);

      console.log('   📊 Нереализованная прибыль (открытые позиции):');
      console.log(`      → $${totalUnrealizedPnl.toFixed(2)} ← ЭТО НЕ отображается на графике\n`);

      if (totalRealizedPnl === 0) {
        console.log('   💡 Решение: Чтобы появились графики, нужно:');
        console.log('      1. Закрыть несколько позиций с прибылью');
        console.log('      2. Подождать 5-10 минут для обновления API Polymarket');
        console.log('      3. График P&L начнет отображать данные\n');
      }
    }

    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
    console.log('✅ Проверка завершена!\n');
    console.log(`📱 Ваш профиль: https://polymarket.com/profile/${PROXY_WALLET}\n`);

  } catch (error) {
    console.error('❌ Ошибка при получении данных:', error);
  }
};

checkMyStats();

