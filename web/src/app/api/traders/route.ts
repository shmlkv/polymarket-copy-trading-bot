import { NextResponse } from 'next/server';
import * as fs from 'fs';
import * as path from 'path';

export interface MonthlyStats {
  month: string;
  totalBought: number;
  totalSold: number;
  netFlow: number;
  tradeCount: number;
  buyCount: number;
  sellCount: number;
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
  topWinners: { title: string; outcome: string; pnl: number; roi: number }[];
  topLosers: { title: string; outcome: string; pnl: number; roi: number }[];
}

export async function GET() {
  try {
    const reportsDir = path.join(process.cwd(), '..', 'trader_reports');

    if (!fs.existsSync(reportsDir)) {
      return NextResponse.json(
        { error: 'trader_reports directory not found. Run the analyzeAllTraders script first.' },
        { status: 404 }
      );
    }

    // Try to read summary file first
    const summaryPath = path.join(reportsDir, '_SUMMARY.json');

    if (fs.existsSync(summaryPath)) {
      const summaryData = fs.readFileSync(summaryPath, 'utf-8');
      const traders: TraderAnalysis[] = JSON.parse(summaryData);
      return NextResponse.json({ traders });
    }

    // Fallback: read individual JSON files
    const files = fs.readdirSync(reportsDir);
    const jsonFiles = files.filter(f => f.endsWith('.json') && !f.startsWith('_'));

    const traders: TraderAnalysis[] = [];

    for (const file of jsonFiles) {
      const filePath = path.join(reportsDir, file);
      const content = fs.readFileSync(filePath, 'utf-8');
      const trader = JSON.parse(content);
      traders.push(trader);
    }

    return NextResponse.json({ traders });
  } catch (error) {
    console.error('Error reading trader reports:', error);
    return NextResponse.json(
      { error: 'Failed to read trader reports' },
      { status: 500 }
    );
  }
}
