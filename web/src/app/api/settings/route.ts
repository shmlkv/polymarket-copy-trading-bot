import { NextResponse } from 'next/server';
import * as fs from 'fs';
import * as path from 'path';
import { BotSettings, SettingsResponse, SettingsUpdate } from '@/types/settings';

const ENV_PATH = path.join(process.cwd(), '..', '.env');
const REPORTS_DIR = path.join(process.cwd(), '..', 'trader_reports');

// Parse .env file into key-value pairs
function parseEnvFile(content: string): Record<string, string> {
  const result: Record<string, string> = {};
  const lines = content.split('\n');

  for (const line of lines) {
    const trimmed = line.trim();
    // Skip comments and empty lines
    if (!trimmed || trimmed.startsWith('#')) continue;

    const equalIndex = trimmed.indexOf('=');
    if (equalIndex === -1) continue;

    const key = trimmed.slice(0, equalIndex).trim();
    let value = trimmed.slice(equalIndex + 1).trim();

    // Remove surrounding quotes if present
    if ((value.startsWith("'") && value.endsWith("'")) ||
        (value.startsWith('"') && value.endsWith('"'))) {
      value = value.slice(1, -1);
    }

    // Handle inline comments
    const commentIndex = value.indexOf(' #');
    if (commentIndex !== -1) {
      value = value.slice(0, commentIndex).trim();
    }

    result[key] = value;
  }

  return result;
}

// Remove surrounding quotes from a string
function removeQuotes(s: string): string {
  const trimmed = s.trim();
  if ((trimmed.startsWith("'") && trimmed.endsWith("'")) ||
      (trimmed.startsWith('"') && trimmed.endsWith('"'))) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

// Convert env values to BotSettings
function envToSettings(env: Record<string, string>): BotSettings {
  // Parse USER_ADDRESSES (can be comma-separated or JSON array)
  let traders: string[] = [];
  const userAddresses = removeQuotes(env.USER_ADDRESSES || '');
  if (userAddresses.trim().startsWith('[')) {
    try {
      traders = JSON.parse(userAddresses);
    } catch {
      traders = userAddresses.split(',').map(s => removeQuotes(s)).filter(Boolean);
    }
  } else {
    traders = userAddresses.split(',').map(s => removeQuotes(s)).filter(Boolean);
  }

  return {
    traders,
    copyStrategy: {
      strategy: (env.COPY_STRATEGY || 'PERCENTAGE').toUpperCase() as BotSettings['copyStrategy']['strategy'],
      copySize: parseFloat(env.COPY_SIZE || env.COPY_PERCENTAGE || '10'),
      tradeMultiplier: parseFloat(env.TRADE_MULTIPLIER || '1'),
      tieredMultipliers: env.TIERED_MULTIPLIERS || null,
    },
    safetyLimits: {
      maxOrderSizeUSD: parseFloat(env.MAX_ORDER_SIZE_USD || '100'),
      minOrderSizeUSD: parseFloat(env.MIN_ORDER_SIZE_USD || '1'),
      maxPositionSizeUSD: env.MAX_POSITION_SIZE_USD ? parseFloat(env.MAX_POSITION_SIZE_USD) : null,
      maxDailyVolumeUSD: env.MAX_DAILY_VOLUME_USD ? parseFloat(env.MAX_DAILY_VOLUME_USD) : null,
    },
    adaptiveStrategy: {
      minPercent: parseFloat(env.ADAPTIVE_MIN_PERCENT || '5'),
      maxPercent: parseFloat(env.ADAPTIVE_MAX_PERCENT || '20'),
      thresholdUSD: parseFloat(env.ADAPTIVE_THRESHOLD_USD || '500'),
    },
    botSettings: {
      fetchInterval: parseInt(env.FETCH_INTERVAL || '1', 10),
      tooOldTimestamp: parseInt(env.TOO_OLD_TIMESTAMP || '24', 10),
      retryLimit: parseInt(env.RETRY_LIMIT || '3', 10),
      tradeAggregationEnabled: env.TRADE_AGGREGATION_ENABLED === 'true',
      tradeAggregationWindowSeconds: parseInt(env.TRADE_AGGREGATION_WINDOW_SECONDS || '300', 10),
      previewMode: env.PREVIEW_MODE === 'true',
    },
    network: {
      requestTimeoutMs: parseInt(env.REQUEST_TIMEOUT_MS || '10000', 10),
      networkRetryLimit: parseInt(env.NETWORK_RETRY_LIMIT || '3', 10),
    },
    wallet: {
      proxyWallet: env.PROXY_WALLET || '',
      usdcContract: env.USDC_CONTRACT_ADDRESS || '',
    },
  };
}

// Get trader labels from trader_reports
function getTraderLabels(): Record<string, string> {
  const labels: Record<string, string> = {};

  try {
    if (fs.existsSync(REPORTS_DIR)) {
      const summaryPath = path.join(REPORTS_DIR, '_SUMMARY.json');
      if (fs.existsSync(summaryPath)) {
        const data = JSON.parse(fs.readFileSync(summaryPath, 'utf-8'));
        for (const trader of data) {
          if (trader.address && trader.label) {
            labels[trader.address.toLowerCase()] = trader.label;
          }
        }
      }
    }
  } catch (error) {
    console.error('Error reading trader labels:', error);
  }

  return labels;
}

// Update .env file with new settings
function updateEnvFile(envContent: string, updates: Record<string, string | null>): string {
  const lines = envContent.split('\n');
  const updatedKeys = new Set<string>();

  // Update existing lines
  const updatedLines = lines.map(line => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) return line;

    const equalIndex = trimmed.indexOf('=');
    if (equalIndex === -1) return line;

    const key = trimmed.slice(0, equalIndex).trim();

    if (key in updates) {
      updatedKeys.add(key);
      const value = updates[key];
      if (value === null) {
        // Comment out the line
        return `# ${line}`;
      }
      // Keep any leading whitespace from original line
      const leadingWhitespace = line.match(/^\s*/)?.[0] || '';
      return `${leadingWhitespace}${key} = ${formatEnvValue(value)}`;
    }

    return line;
  });

  // Add new keys that weren't in the file
  for (const [key, value] of Object.entries(updates)) {
    if (!updatedKeys.has(key) && value !== null) {
      updatedLines.push(`${key} = ${formatEnvValue(value)}`);
    }
  }

  return updatedLines.join('\n');
}

// Format value for .env file
function formatEnvValue(value: string): string {
  // If value contains spaces or special chars, wrap in quotes
  if (value.includes(' ') || value.includes(',') || value.includes('#')) {
    return `'${value}'`;
  }
  return value;
}

// Convert settings update to env key-value pairs
function settingsToEnvUpdates(update: SettingsUpdate): Record<string, string | null> {
  const envUpdates: Record<string, string | null> = {};

  if (update.traders !== undefined) {
    envUpdates.USER_ADDRESSES = update.traders.join(',');
  }

  if (update.copyStrategy) {
    if (update.copyStrategy.strategy !== undefined) {
      envUpdates.COPY_STRATEGY = update.copyStrategy.strategy;
    }
    if (update.copyStrategy.copySize !== undefined) {
      envUpdates.COPY_SIZE = update.copyStrategy.copySize.toString();
      envUpdates.COPY_PERCENTAGE = update.copyStrategy.copySize.toString();
    }
    if (update.copyStrategy.tradeMultiplier !== undefined) {
      envUpdates.TRADE_MULTIPLIER = update.copyStrategy.tradeMultiplier.toString();
    }
    if (update.copyStrategy.tieredMultipliers !== undefined) {
      envUpdates.TIERED_MULTIPLIERS = update.copyStrategy.tieredMultipliers || '';
    }
  }

  if (update.safetyLimits) {
    if (update.safetyLimits.maxOrderSizeUSD !== undefined) {
      envUpdates.MAX_ORDER_SIZE_USD = update.safetyLimits.maxOrderSizeUSD.toString();
    }
    if (update.safetyLimits.minOrderSizeUSD !== undefined) {
      envUpdates.MIN_ORDER_SIZE_USD = update.safetyLimits.minOrderSizeUSD.toString();
    }
    if (update.safetyLimits.maxPositionSizeUSD !== undefined) {
      envUpdates.MAX_POSITION_SIZE_USD = update.safetyLimits.maxPositionSizeUSD?.toString() || '';
    }
    if (update.safetyLimits.maxDailyVolumeUSD !== undefined) {
      envUpdates.MAX_DAILY_VOLUME_USD = update.safetyLimits.maxDailyVolumeUSD?.toString() || '';
    }
  }

  if (update.adaptiveStrategy) {
    if (update.adaptiveStrategy.minPercent !== undefined) {
      envUpdates.ADAPTIVE_MIN_PERCENT = update.adaptiveStrategy.minPercent.toString();
    }
    if (update.adaptiveStrategy.maxPercent !== undefined) {
      envUpdates.ADAPTIVE_MAX_PERCENT = update.adaptiveStrategy.maxPercent.toString();
    }
    if (update.adaptiveStrategy.thresholdUSD !== undefined) {
      envUpdates.ADAPTIVE_THRESHOLD_USD = update.adaptiveStrategy.thresholdUSD.toString();
    }
  }

  if (update.botSettings) {
    if (update.botSettings.fetchInterval !== undefined) {
      envUpdates.FETCH_INTERVAL = update.botSettings.fetchInterval.toString();
    }
    if (update.botSettings.tooOldTimestamp !== undefined) {
      envUpdates.TOO_OLD_TIMESTAMP = update.botSettings.tooOldTimestamp.toString();
    }
    if (update.botSettings.retryLimit !== undefined) {
      envUpdates.RETRY_LIMIT = update.botSettings.retryLimit.toString();
    }
    if (update.botSettings.tradeAggregationEnabled !== undefined) {
      envUpdates.TRADE_AGGREGATION_ENABLED = update.botSettings.tradeAggregationEnabled.toString();
    }
    if (update.botSettings.tradeAggregationWindowSeconds !== undefined) {
      envUpdates.TRADE_AGGREGATION_WINDOW_SECONDS = update.botSettings.tradeAggregationWindowSeconds.toString();
    }
    if (update.botSettings.previewMode !== undefined) {
      envUpdates.PREVIEW_MODE = update.botSettings.previewMode.toString();
    }
  }

  if (update.network) {
    if (update.network.requestTimeoutMs !== undefined) {
      envUpdates.REQUEST_TIMEOUT_MS = update.network.requestTimeoutMs.toString();
    }
    if (update.network.networkRetryLimit !== undefined) {
      envUpdates.NETWORK_RETRY_LIMIT = update.network.networkRetryLimit.toString();
    }
  }

  return envUpdates;
}

export async function GET() {
  try {
    if (!fs.existsSync(ENV_PATH)) {
      return NextResponse.json(
        { error: '.env file not found' },
        { status: 404 }
      );
    }

    const envContent = fs.readFileSync(ENV_PATH, 'utf-8');
    const env = parseEnvFile(envContent);
    const settings = envToSettings(env);
    const traderLabels = getTraderLabels();

    const response: SettingsResponse = {
      settings,
      traderLabels,
    };

    return NextResponse.json(response);
  } catch (error) {
    console.error('Error reading settings:', error);
    return NextResponse.json(
      { error: 'Failed to read settings' },
      { status: 500 }
    );
  }
}

export async function PUT(request: Request) {
  try {
    const update: SettingsUpdate = await request.json();

    if (!fs.existsSync(ENV_PATH)) {
      return NextResponse.json(
        { error: '.env file not found' },
        { status: 404 }
      );
    }

    const envContent = fs.readFileSync(ENV_PATH, 'utf-8');
    const envUpdates = settingsToEnvUpdates(update);
    const newEnvContent = updateEnvFile(envContent, envUpdates);

    // Write updated .env file
    fs.writeFileSync(ENV_PATH, newEnvContent, 'utf-8');

    // Read back and return updated settings
    const newEnv = parseEnvFile(newEnvContent);
    const settings = envToSettings(newEnv);
    const traderLabels = getTraderLabels();

    return NextResponse.json({
      success: true,
      settings,
      traderLabels,
      message: 'Settings updated. Restart the bot to apply changes.',
    });
  } catch (error) {
    console.error('Error updating settings:', error);
    return NextResponse.json(
      { error: 'Failed to update settings' },
      { status: 500 }
    );
  }
}
