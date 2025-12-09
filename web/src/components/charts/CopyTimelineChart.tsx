'use client';

import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from 'recharts';
import { CopyTrade } from '@/types/myTrades';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

interface CopyTimelineChartProps {
  trades: CopyTrade[];
}

export function CopyTimelineChart({ trades }: CopyTimelineChartProps) {
  // Group trades by day and calculate cumulative P&L
  const sortedTrades = [...trades].sort((a, b) => a.timestamp - b.timestamp);

  const dailyData = new Map<string, { bought: number; sold: number }>();

  for (const trade of sortedTrades) {
    const date = new Date(trade.timestamp * 1000).toISOString().split('T')[0];

    if (!dailyData.has(date)) {
      dailyData.set(date, { bought: 0, sold: 0 });
    }

    const day = dailyData.get(date)!;
    if (trade.side === 'BUY') {
      day.bought += trade.usdcSize;
    } else {
      day.sold += trade.usdcSize;
    }
  }

  // Build cumulative data
  let cumPnL = 0;
  const data = Array.from(dailyData.entries())
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([date, { bought, sold }]) => {
      const dailyPnL = sold - bought;
      cumPnL += dailyPnL;
      return {
        date: date.slice(5), // MM-DD format
        fullDate: date,
        dailyPnL: Number(dailyPnL.toFixed(2)),
        cumPnL: Number(cumPnL.toFixed(2)),
      };
    });

  if (data.length === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Cumulative P&L Over Time</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-muted-foreground">No trade data available</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Cumulative P&L Over Time</CardTitle>
      </CardHeader>
      <CardContent>
        <ResponsiveContainer width="100%" height={400}>
          <LineChart data={data} margin={{ top: 20, right: 30, left: 20, bottom: 20 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#333" />
            <XAxis dataKey="date" tick={{ fill: '#888' }} />
            <YAxis
              tick={{ fill: '#888' }}
              tickFormatter={(value) => `$${value}`}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: '#1a1a1a',
                border: '1px solid #333',
                borderRadius: '8px',
                color: '#fff',
              }}
              labelStyle={{ color: '#fff' }}
              itemStyle={{ color: '#fff' }}
              formatter={(value: number) => [`$${value.toFixed(2)}`, '']}
              labelFormatter={(label, payload) => {
                if (payload && payload[0]) {
                  return payload[0].payload.fullDate;
                }
                return label;
              }}
            />
            <Legend />
            <Line
              type="monotone"
              dataKey="cumPnL"
              name="Cumulative P&L"
              stroke="#3b82f6"
              strokeWidth={2}
              dot={{ fill: '#3b82f6', r: 3 }}
              activeDot={{ r: 5 }}
            />
            <Line
              type="monotone"
              dataKey="dailyPnL"
              name="Daily P&L"
              stroke="#888"
              strokeWidth={1}
              strokeDasharray="5 5"
              dot={false}
            />
          </LineChart>
        </ResponsiveContainer>
      </CardContent>
    </Card>
  );
}
