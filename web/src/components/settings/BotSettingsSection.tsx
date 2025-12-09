'use client';

import { Card, CardHeader, CardTitle, CardContent, CardDescription } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Switch } from '@/components/ui/switch';
import { Badge } from '@/components/ui/badge';
import { BotSettings, BalanceInfo } from '@/types/settings';

interface BotSettingsSectionProps {
  botSettings: BotSettings['botSettings'];
  network: BotSettings['network'];
  wallet: BotSettings['wallet'];
  balance: BalanceInfo | null;
  onBotSettingsChange: (update: Partial<BotSettings['botSettings']>) => void;
  onNetworkChange: (update: Partial<BotSettings['network']>) => void;
}

export function BotSettingsSection({
  botSettings,
  network,
  wallet,
  balance,
  onBotSettingsChange,
  onNetworkChange,
}: BotSettingsSectionProps) {
  const truncateAddress = (address: string): string => {
    if (!address) return 'Not configured';
    return `${address.slice(0, 10)}...${address.slice(-8)}`;
  };

  return (
    <div className="space-y-6">
      {/* Bot Mode */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-3">
            Bot Mode
            {botSettings.previewMode ? (
              <Badge variant="warning">Preview Mode</Badge>
            ) : (
              <Badge variant="success">Live Trading</Badge>
            )}
          </CardTitle>
          <CardDescription>
            Control whether the bot executes real trades
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Switch
            checked={botSettings.previewMode}
            onCheckedChange={(checked) => onBotSettingsChange({ previewMode: checked })}
            label="Preview Mode"
            description="Monitor trades but don't execute them (safe testing)"
          />
        </CardContent>
      </Card>

      {/* Wallet Info */}
      <Card>
        <CardHeader>
          <CardTitle>Wallet Info</CardTitle>
          <CardDescription>Your trading wallet (read-only)</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-3 bg-muted/50 rounded-lg">
              <p className="text-xs text-muted-foreground mb-1">Proxy Wallet</p>
              <code className="text-sm font-mono">{truncateAddress(wallet.proxyWallet)}</code>
            </div>
            <div className="p-3 bg-muted/50 rounded-lg">
              <p className="text-xs text-muted-foreground mb-1">USDC Contract</p>
              <code className="text-sm font-mono">{truncateAddress(wallet.usdcContract)}</code>
            </div>
          </div>

          {balance && (
            <div className="grid grid-cols-2 gap-4">
              <div className="p-3 bg-muted/50 rounded-lg">
                <p className="text-xs text-muted-foreground mb-1">USDC Balance</p>
                <p className={`text-xl font-bold font-mono ${balance.usdc < 10 ? 'text-yellow-500' : 'text-green-500'}`}>
                  ${balance.usdc.toFixed(2)}
                </p>
              </div>
              <div className="p-3 bg-muted/50 rounded-lg">
                <p className="text-xs text-muted-foreground mb-1">MATIC Balance (gas)</p>
                <p className={`text-xl font-bold font-mono ${balance.matic < 0.1 ? 'text-yellow-500' : ''}`}>
                  {balance.matic.toFixed(4)}
                </p>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Monitoring Settings */}
      <Card>
        <CardHeader>
          <CardTitle>Monitoring Settings</CardTitle>
          <CardDescription>Configure how the bot monitors traders</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <Input
              label="Fetch Interval (seconds)"
              type="number"
              min={1}
              value={botSettings.fetchInterval}
              onChange={(e) => onBotSettingsChange({ fetchInterval: parseInt(e.target.value) || 1 })}
            />
            <Input
              label="Ignore Trades Older Than (hours)"
              type="number"
              min={1}
              value={botSettings.tooOldTimestamp}
              onChange={(e) => onBotSettingsChange({ tooOldTimestamp: parseInt(e.target.value) || 24 })}
            />
            <Input
              label="Retry Limit"
              type="number"
              min={1}
              max={10}
              value={botSettings.retryLimit}
              onChange={(e) => onBotSettingsChange({ retryLimit: parseInt(e.target.value) || 3 })}
            />
          </div>

          <div className="border-t pt-4 space-y-4">
            <Switch
              checked={botSettings.tradeAggregationEnabled}
              onCheckedChange={(checked) => onBotSettingsChange({ tradeAggregationEnabled: checked })}
              label="Trade Aggregation"
              description="Combine multiple small trades into one larger trade"
            />

            {botSettings.tradeAggregationEnabled && (
              <Input
                label="Aggregation Window (seconds)"
                type="number"
                min={60}
                value={botSettings.tradeAggregationWindowSeconds}
                onChange={(e) => onBotSettingsChange({
                  tradeAggregationWindowSeconds: parseInt(e.target.value) || 300
                })}
              />
            )}
          </div>
        </CardContent>
      </Card>

      {/* Network Settings */}
      <Card>
        <CardHeader>
          <CardTitle>Network Settings</CardTitle>
          <CardDescription>Configure API timeouts and retries</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Input
              label="Request Timeout (ms)"
              type="number"
              min={1000}
              step={1000}
              value={network.requestTimeoutMs}
              onChange={(e) => onNetworkChange({ requestTimeoutMs: parseInt(e.target.value) || 10000 })}
            />
            <Input
              label="Network Retry Limit"
              type="number"
              min={1}
              max={10}
              value={network.networkRetryLimit}
              onChange={(e) => onNetworkChange({ networkRetryLimit: parseInt(e.target.value) || 3 })}
            />
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
