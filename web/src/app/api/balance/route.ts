import { NextResponse } from 'next/server';
import { BalanceInfo } from '@/types/settings';
import * as fs from 'fs';
import * as path from 'path';

const ENV_PATH = path.join(process.cwd(), '..', '.env');

function getEnvValue(key: string): string | undefined {
  try {
    if (!fs.existsSync(ENV_PATH)) return undefined;
    const content = fs.readFileSync(ENV_PATH, 'utf-8');
    const lines = content.split('\n');

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;

      const equalIndex = trimmed.indexOf('=');
      if (equalIndex === -1) continue;

      const lineKey = trimmed.slice(0, equalIndex).trim();
      if (lineKey === key) {
        let value = trimmed.slice(equalIndex + 1).trim();
        if ((value.startsWith("'") && value.endsWith("'")) ||
            (value.startsWith('"') && value.endsWith('"'))) {
          value = value.slice(1, -1);
        }
        return value;
      }
    }
  } catch {
    return undefined;
  }
  return undefined;
}

export async function GET() {
  try {
    const rpcUrl = getEnvValue('RPC_URL');
    const proxyWallet = getEnvValue('PROXY_WALLET');
    const usdcContract = getEnvValue('USDC_CONTRACT_ADDRESS') || '0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174';

    if (!rpcUrl || !proxyWallet) {
      return NextResponse.json(
        { error: 'Wallet or RPC not configured' },
        { status: 400 }
      );
    }

    const result: BalanceInfo = {
      usdc: 0,
      matic: 0,
      proxyWallet,
    };

    // Get USDC balance (ERC20 balanceOf)
    const usdcData = `0x70a08231000000000000000000000000${proxyWallet.slice(2).toLowerCase()}`;
    const usdcResponse = await fetch(rpcUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        method: 'eth_call',
        params: [{ to: usdcContract, data: usdcData }, 'latest'],
        id: 1,
      }),
    });

    if (usdcResponse.ok) {
      const json = await usdcResponse.json();
      if (json.result) {
        const balanceWei = BigInt(json.result);
        result.usdc = Number(balanceWei) / 1e6; // USDC has 6 decimals
      }
    }

    // Get MATIC balance (native token)
    const maticResponse = await fetch(rpcUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        method: 'eth_getBalance',
        params: [proxyWallet, 'latest'],
        id: 2,
      }),
    });

    if (maticResponse.ok) {
      const json = await maticResponse.json();
      if (json.result) {
        const balanceWei = BigInt(json.result);
        result.matic = Number(balanceWei) / 1e18; // MATIC has 18 decimals
      }
    }

    return NextResponse.json(result);
  } catch (error) {
    console.error('Error fetching balance:', error);
    return NextResponse.json(
      { error: 'Failed to fetch balance' },
      { status: 500 }
    );
  }
}
