export interface MonthlyStats {
  month: string;
  totalBought: number;
  totalSold: number;
  netFlow: number;
  tradeCount: number;
  buyCount: number;
  sellCount: number;
  realizedPnl: number;
}

export interface DailyStats {
  date: string;
  totalBought: number;
  totalSold: number;
  netFlow: number;
  tradeCount: number;
  buyCount: number;
  sellCount: number;
  realizedPnl: number;
}

export interface TraderAnalysis {
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
  dailyBreakdown?: DailyStats[];
  topWinners: { title: string; outcome: string; pnl: number; roi: number }[];
  topLosers: { title: string; outcome: string; pnl: number; roi: number }[];
}
