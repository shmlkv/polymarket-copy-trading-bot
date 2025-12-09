export type CopyStrategy = 'PERCENTAGE' | 'FIXED' | 'ADAPTIVE';

export interface MultiplierTier {
  min: number;
  max: number | null; // null = infinity
  multiplier: number;
}

export interface BotSettings {
  // Traders to copy
  traders: string[];

  // Copy Strategy
  copyStrategy: {
    strategy: CopyStrategy;
    copySize: number;
    tradeMultiplier: number;
    tieredMultipliers: string | null; // raw string from .env
  };

  // Safety Limits
  safetyLimits: {
    maxOrderSizeUSD: number;
    minOrderSizeUSD: number;
    maxPositionSizeUSD: number | null;
    maxDailyVolumeUSD: number | null;
  };

  // Adaptive Strategy (only when strategy = ADAPTIVE)
  adaptiveStrategy: {
    minPercent: number;
    maxPercent: number;
    thresholdUSD: number;
  };

  // Bot Settings
  botSettings: {
    fetchInterval: number;
    tooOldTimestamp: number;
    retryLimit: number;
    tradeAggregationEnabled: boolean;
    tradeAggregationWindowSeconds: number;
    previewMode: boolean;
  };

  // Network Settings
  network: {
    requestTimeoutMs: number;
    networkRetryLimit: number;
  };

  // Wallet Info (read-only)
  wallet: {
    proxyWallet: string;
    usdcContract: string;
  };
}

export interface SettingsResponse {
  settings: BotSettings;
  traderLabels: Record<string, string>; // address -> label
}

export interface HealthCheckResult {
  healthy: boolean;
  checks: {
    database: { status: 'ok' | 'error'; message?: string };
    rpc: { status: 'ok' | 'error'; message?: string };
    balance: { status: 'ok' | 'warning' | 'error'; value?: number; message?: string };
    api: { status: 'ok' | 'error'; message?: string };
  };
  timestamp: string;
}

export interface BalanceInfo {
  usdc: number;
  matic: number;
  proxyWallet: string;
}

export type ActionType =
  | 'health-check'
  | 'check-stats'
  | 'manual-sell'
  | 'close-resolved'
  | 'redeem-resolved'
  | 'close-stale';

export interface ActionRequest {
  action: ActionType;
  params?: {
    keyword?: string; // for manual-sell
  };
}

export interface ActionResponse {
  success: boolean;
  action: ActionType;
  output: string;
  error?: string;
}

// Helper type for partial settings updates
export type SettingsUpdate = Partial<{
  traders: string[];
  copyStrategy: Partial<BotSettings['copyStrategy']>;
  safetyLimits: Partial<BotSettings['safetyLimits']>;
  adaptiveStrategy: Partial<BotSettings['adaptiveStrategy']>;
  botSettings: Partial<BotSettings['botSettings']>;
  network: Partial<BotSettings['network']>;
}>;
