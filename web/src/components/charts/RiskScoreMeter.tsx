'use client';

import { TraderAnalysis } from '@/types/trader';
import { TimeRange } from '@/components/TimeRangeFilter';

interface RiskScoreMeterProps {
  traders: TraderAnalysis[];
  timeRange?: TimeRange;
}

export function RiskScoreMeter({ traders }: RiskScoreMeterProps) {
  // Calculate risk score based on multiple factors
  const calculateRiskScore = () => {
    if (traders.length === 0) return 50;

    let riskFactors = 0;
    let maxFactors = 0;

    // Factor 1: Average ROI volatility (higher = more risk)
    const rois = traders.map((t) => t.pnl.roi);
    const avgRoi = rois.reduce((a, b) => a + b, 0) / rois.length;
    const roiVariance = rois.reduce((sum, r) => sum + Math.pow(r - avgRoi, 2), 0) / rois.length;
    const roiStdDev = Math.sqrt(roiVariance);
    riskFactors += Math.min(roiStdDev / 50, 1) * 30; // Max 30 points
    maxFactors += 30;

    // Factor 2: Percentage of losing traders
    const losingPct = traders.filter((t) => t.pnl.total < 0).length / traders.length;
    riskFactors += losingPct * 30; // Max 30 points
    maxFactors += 30;

    // Factor 3: Average win rate (lower = more risk)
    const avgWinRate = traders.reduce((sum, t) => sum + t.positions.winRate, 0) / traders.length;
    riskFactors += (1 - avgWinRate / 100) * 20; // Max 20 points
    maxFactors += 20;

    // Factor 4: Concentration (if few traders, higher risk)
    const concentrationRisk = Math.max(0, (5 - traders.length) / 5) * 20;
    riskFactors += concentrationRisk;
    maxFactors += 20;

    return Math.round((riskFactors / maxFactors) * 100);
  };

  const riskScore = calculateRiskScore();

  // Risk level
  const getRiskLevel = (score: number) => {
    if (score <= 33) return { label: 'Low', color: '#22c55e' };
    if (score <= 66) return { label: 'Medium', color: '#eab308' };
    return { label: 'High', color: '#ef4444' };
  };

  const { label, color } = getRiskLevel(riskScore);

  // SVG parameters for semicircle gauge
  const size = 140;
  const strokeWidth = 14;
  const radius = (size - strokeWidth) / 2;
  const circumference = Math.PI * radius;
  const progress = (riskScore / 100) * circumference;

  return (
    <div className="bg-card rounded-xl border p-4 flex flex-col items-center justify-center h-full">
      <span className="text-sm text-muted-foreground mb-2">Risk Score</span>
      <div className="relative" style={{ width: size, height: size / 2 + 20 }}>
        <svg
          width={size}
          height={size / 2 + 20}
          viewBox={`0 0 ${size} ${size / 2 + 20}`}
        >
          {/* Background gradient segments */}
          <defs>
            <linearGradient id="riskGradient" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#22c55e" />
              <stop offset="50%" stopColor="#eab308" />
              <stop offset="100%" stopColor="#ef4444" />
            </linearGradient>
          </defs>
          {/* Background arc */}
          <path
            d={`M ${strokeWidth / 2} ${size / 2} A ${radius} ${radius} 0 0 1 ${size - strokeWidth / 2} ${size / 2}`}
            fill="none"
            stroke="#262626"
            strokeWidth={strokeWidth}
            strokeLinecap="round"
          />
          {/* Colored background showing full range */}
          <path
            d={`M ${strokeWidth / 2} ${size / 2} A ${radius} ${radius} 0 0 1 ${size - strokeWidth / 2} ${size / 2}`}
            fill="none"
            stroke="url(#riskGradient)"
            strokeWidth={strokeWidth}
            strokeLinecap="round"
            opacity={0.3}
          />
          {/* Progress indicator - needle style */}
          <circle
            cx={strokeWidth / 2 + (riskScore / 100) * (size - strokeWidth)}
            cy={size / 2 - Math.sin((riskScore / 100) * Math.PI) * radius}
            r={6}
            fill={color}
            stroke="#0a0a0a"
            strokeWidth={2}
          />
        </svg>
        {/* Center text */}
        <div className="absolute inset-0 flex flex-col items-center justify-end pb-0">
          <span className="text-3xl font-bold font-mono" style={{ color }}>
            {riskScore}
          </span>
          <span className="text-xs font-medium" style={{ color }}>
            {label}
          </span>
        </div>
      </div>
    </div>
  );
}
