'use client';

import { Card, CardHeader, CardTitle, CardContent, CardDescription } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Select } from '@/components/ui/select';
import { TieredMultipliersEditor } from './TieredMultipliersEditor';
import { BotSettings, CopyStrategy } from '@/types/settings';

interface CopyStrategySectionProps {
  copyStrategy: BotSettings['copyStrategy'];
  adaptiveStrategy: BotSettings['adaptiveStrategy'];
  onCopyStrategyChange: (update: Partial<BotSettings['copyStrategy']>) => void;
  onAdaptiveStrategyChange: (update: Partial<BotSettings['adaptiveStrategy']>) => void;
}

const strategyOptions = [
  { value: 'PERCENTAGE', label: 'Percentage' },
  { value: 'FIXED', label: 'Fixed Amount' },
  { value: 'ADAPTIVE', label: 'Adaptive' },
];

const strategyDescriptions: Record<CopyStrategy, string> = {
  PERCENTAGE: 'Copy a fixed percentage of trader\'s order size',
  FIXED: 'Copy a fixed dollar amount per trade',
  ADAPTIVE: 'Dynamically adjust percentage based on trade size',
};

export function CopyStrategySection({
  copyStrategy,
  adaptiveStrategy,
  onCopyStrategyChange,
  onAdaptiveStrategyChange,
}: CopyStrategySectionProps) {
  const isAdaptive = copyStrategy.strategy === 'ADAPTIVE';

  return (
    <Card>
      <CardHeader>
        <CardTitle>Copy Strategy</CardTitle>
        <CardDescription>
          Configure how trades are copied from followed traders
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Strategy Selection */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Select
            label="Strategy Type"
            value={copyStrategy.strategy}
            onValueChange={(value) => onCopyStrategyChange({ strategy: value as CopyStrategy })}
            options={strategyOptions}
          />
          <div className="flex items-end">
            <p className="text-sm text-muted-foreground pb-2">
              {strategyDescriptions[copyStrategy.strategy]}
            </p>
          </div>
        </div>

        {/* Copy Size */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Input
            label={copyStrategy.strategy === 'FIXED' ? 'Fixed Amount ($)' : 'Copy Percentage (%)'}
            type="number"
            step="0.1"
            value={copyStrategy.copySize}
            onChange={(e) => onCopyStrategyChange({ copySize: parseFloat(e.target.value) || 0 })}
          />
          <Input
            label="Trade Multiplier"
            type="number"
            step="0.1"
            value={copyStrategy.tradeMultiplier}
            onChange={(e) => onCopyStrategyChange({ tradeMultiplier: parseFloat(e.target.value) || 1 })}
          />
        </div>

        {/* Adaptive Strategy Options */}
        {isAdaptive && (
          <div className="p-4 border rounded-lg bg-muted/30 space-y-4">
            <h4 className="font-medium text-sm">Adaptive Strategy Settings</h4>
            <p className="text-xs text-muted-foreground">
              Small orders use higher %, large orders use lower %
            </p>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <Input
                label="Min Percent (%)"
                type="number"
                step="0.1"
                value={adaptiveStrategy.minPercent}
                onChange={(e) => onAdaptiveStrategyChange({ minPercent: parseFloat(e.target.value) || 0 })}
              />
              <Input
                label="Max Percent (%)"
                type="number"
                step="0.1"
                value={adaptiveStrategy.maxPercent}
                onChange={(e) => onAdaptiveStrategyChange({ maxPercent: parseFloat(e.target.value) || 0 })}
              />
              <Input
                label="Threshold ($)"
                type="number"
                step="1"
                value={adaptiveStrategy.thresholdUSD}
                onChange={(e) => onAdaptiveStrategyChange({ thresholdUSD: parseFloat(e.target.value) || 0 })}
              />
            </div>
          </div>
        )}

        {/* Tiered Multipliers */}
        <div className="p-4 border rounded-lg space-y-4">
          <h4 className="font-medium text-sm">Tiered Multipliers (Optional)</h4>
          <TieredMultipliersEditor
            value={copyStrategy.tieredMultipliers}
            onChange={(value) => onCopyStrategyChange({ tieredMultipliers: value })}
          />
        </div>

        {/* Preview */}
        <div className="text-xs text-muted-foreground bg-muted/50 p-3 rounded-lg">
          <p className="font-medium mb-2">Example calculation:</p>
          {copyStrategy.strategy === 'PERCENTAGE' && (
            <p>
              Trader buys $100 → You buy ${(100 * copyStrategy.copySize / 100 * copyStrategy.tradeMultiplier).toFixed(2)}
              ({copyStrategy.copySize}% × {copyStrategy.tradeMultiplier}x)
            </p>
          )}
          {copyStrategy.strategy === 'FIXED' && (
            <p>
              Trader buys any amount → You buy ${(copyStrategy.copySize * copyStrategy.tradeMultiplier).toFixed(2)}
              (${copyStrategy.copySize} × {copyStrategy.tradeMultiplier}x)
            </p>
          )}
          {copyStrategy.strategy === 'ADAPTIVE' && (
            <>
              <p>
                Small trade ($50) → {adaptiveStrategy.maxPercent}% = ${(50 * adaptiveStrategy.maxPercent / 100).toFixed(2)}
              </p>
              <p>
                Large trade ($1000) → {adaptiveStrategy.minPercent}% = ${(1000 * adaptiveStrategy.minPercent / 100).toFixed(2)}
              </p>
            </>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
