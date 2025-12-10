import { AssetType, ClobClient, OrderType, Side } from '@polymarket/clob-client';
import { ethers } from 'ethers';
import { ENV } from '../config/env';
import fetchData from '../utils/fetchData';
import Logger from '../utils/logger';

const PROXY_WALLET = ENV.PROXY_WALLET;
const PRIVATE_KEY = ENV.PRIVATE_KEY;
const RPC_URL = ENV.RPC_URL;
const RETRY_LIMIT = ENV.RETRY_LIMIT;

// Auto-resolver configuration from ENV
const AUTO_RESOLVE_ENABLED = ENV.AUTO_RESOLVE_ENABLED;
const AUTO_RESOLVE_INTERVAL = ENV.AUTO_RESOLVE_INTERVAL;

// Contract addresses on Polygon
const CTF_CONTRACT_ADDRESS = '0x4D97DCd97eC945f40cF65F87097ACe5EA0476045';
const USDC_ADDRESS = '0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174';

// CTF Contract ABI (only the functions we need)
const CTF_ABI = [
    'function redeemPositions(address collateralToken, bytes32 parentCollectionId, bytes32 conditionId, uint256[] calldata indexSets) external',
    'function balanceOf(address owner, uint256 tokenId) external view returns (uint256)',
];

// Polymarket enforces a 1 token minimum on sell orders
const MIN_SELL_TOKENS = 1.0;
const ZERO_THRESHOLD = 0.0001;

// Thresholds for considering a position "resolved"
const RESOLVED_HIGH = 0.99; // Position won (price ~$1)
const RESOLVED_LOW = 0.01; // Position lost (price ~$0)

interface Position {
    asset: string;
    conditionId: string;
    size: number;
    avgPrice: number;
    currentValue: number;
    curPrice: number;
    title?: string;
    outcome?: string;
    slug?: string;
    redeemable?: boolean;
}

interface ResolveResult {
    method: 'sell' | 'redeem' | 'failed';
    tokens: number;
    proceeds: number;
}

// Track if resolver should continue running
let isRunning = true;

// Lazy-initialized provider and contract
let provider: ethers.providers.JsonRpcProvider | null = null;
let wallet: ethers.Wallet | null = null;
let ctfContract: ethers.Contract | null = null;

const getContract = () => {
    if (!provider) {
        provider = new ethers.providers.JsonRpcProvider(RPC_URL);
        wallet = new ethers.Wallet(PRIVATE_KEY, provider);
        ctfContract = new ethers.Contract(CTF_CONTRACT_ADDRESS, CTF_ABI, wallet);
    }
    return { provider, wallet: wallet!, ctfContract: ctfContract! };
};

/**
 * Stop the auto resolver gracefully
 */
export const stopAutoResolver = () => {
    isRunning = false;
    Logger.info('Auto resolver shutdown requested...');
};

const extractOrderError = (response: unknown): string | undefined => {
    if (!response) {
        return undefined;
    }

    if (typeof response === 'string') {
        return response;
    }

    if (typeof response === 'object') {
        const data = response as Record<string, unknown>;

        const directError = data.error;
        if (typeof directError === 'string') {
            return directError;
        }

        if (typeof directError === 'object' && directError !== null) {
            const nested = directError as Record<string, unknown>;
            if (typeof nested.error === 'string') {
                return nested.error;
            }
            if (typeof nested.message === 'string') {
                return nested.message;
            }
        }

        if (typeof data.errorMsg === 'string') {
            return data.errorMsg;
        }

        if (typeof data.message === 'string') {
            return data.message;
        }
    }

    return undefined;
};

const isInsufficientBalanceOrAllowanceError = (message: string | undefined): boolean => {
    if (!message) {
        return false;
    }
    const lower = message.toLowerCase();
    return lower.includes('not enough balance') || lower.includes('allowance');
};

const updatePolymarketCache = async (clobClient: ClobClient, tokenId: string) => {
    try {
        await clobClient.updateBalanceAllowance({
            asset_type: AssetType.CONDITIONAL,
            token_id: tokenId,
        });
    } catch (error) {
        // Silently ignore cache update errors
    }
};

/**
 * Try to sell position via CLOB orderbook
 * Returns: tokens sold, proceeds, and whether orderbook was available
 */
const trySellPosition = async (
    clobClient: ClobClient,
    position: Position
): Promise<{ sold: number; proceeds: number; orderbookAvailable: boolean }> => {
    let remaining = position.size;
    let attempts = 0;
    let soldTokens = 0;
    let proceedsUsd = 0;
    let orderbookAvailable = true;

    if (remaining < MIN_SELL_TOKENS) {
        return { sold: 0, proceeds: 0, orderbookAvailable: true };
    }

    await updatePolymarketCache(clobClient, position.asset);

    while (remaining >= MIN_SELL_TOKENS && attempts < RETRY_LIMIT) {
        let orderBook;
        try {
            orderBook = await clobClient.getOrderBook(position.asset);
        } catch (error) {
            // Orderbook doesn't exist - market is closed
            orderbookAvailable = false;
            break;
        }

        if (!orderBook.bids || orderBook.bids.length === 0) {
            orderbookAvailable = false;
            break;
        }

        const bestBid = orderBook.bids.reduce((max, bid) => {
            return parseFloat(bid.price) > parseFloat(max.price) ? bid : max;
        }, orderBook.bids[0]);

        const bidSize = parseFloat(bestBid.size);
        const bidPrice = parseFloat(bestBid.price);

        if (bidSize < MIN_SELL_TOKENS) {
            break;
        }

        const sellAmount = Math.min(remaining, bidSize);

        if (sellAmount < MIN_SELL_TOKENS) {
            break;
        }

        const orderArgs = {
            side: Side.SELL,
            tokenID: position.asset,
            amount: sellAmount,
            price: bidPrice,
        };

        try {
            const signedOrder = await clobClient.createMarketOrder(orderArgs);
            const resp = await clobClient.postOrder(signedOrder, OrderType.FOK);

            if (resp.success === true) {
                const tradeValue = sellAmount * bidPrice;
                soldTokens += sellAmount;
                proceedsUsd += tradeValue;
                remaining -= sellAmount;
                attempts = 0;
                Logger.success(
                    `   ✅ Sold ${sellAmount.toFixed(2)} tokens @ $${bidPrice.toFixed(3)} (≈ $${tradeValue.toFixed(2)})`
                );
            } else {
                attempts += 1;
                const errorMessage = extractOrderError(resp);

                if (isInsufficientBalanceOrAllowanceError(errorMessage)) {
                    break;
                }
            }
        } catch (error) {
            attempts += 1;
        }
    }

    return { sold: soldTokens, proceeds: proceedsUsd, orderbookAvailable };
};

/**
 * Redeem position on-chain via CTF contract
 */
const redeemPosition = async (position: Position): Promise<{ success: boolean; error?: string }> => {
    try {
        const { ctfContract, provider } = getContract();

        // Convert conditionId to bytes32 format
        const conditionIdBytes32 = ethers.utils.hexZeroPad(
            ethers.BigNumber.from(position.conditionId).toHexString(),
            32
        );

        // parentCollectionId is always zero for Polymarket
        const parentCollectionId = ethers.constants.HashZero;

        // indexSets: [1, 2] represents both outcome collections
        const indexSets = [1, 2];

        Logger.info(`   🔗 Attempting on-chain redemption...`);

        // Get current gas price from network
        const feeData = await provider!.getFeeData();
        const gasPrice = feeData.gasPrice || feeData.maxFeePerGas;

        if (!gasPrice) {
            throw new Error('Could not determine gas price');
        }

        // Add 20% buffer to ensure transaction goes through
        const adjustedGasPrice = gasPrice.mul(120).div(100);

        const tx = await ctfContract.redeemPositions(
            USDC_ADDRESS,
            parentCollectionId,
            conditionIdBytes32,
            indexSets,
            {
                gasLimit: 500000,
                gasPrice: adjustedGasPrice,
            }
        );

        Logger.info(`   ⏳ TX submitted: ${tx.hash}`);

        const receipt = await tx.wait();

        if (receipt.status === 1) {
            const gasCost = ethers.utils.formatUnits(
                receipt.gasUsed.mul(adjustedGasPrice),
                18
            );
            Logger.success(`   ✅ Redeemed on-chain! Gas: ${parseFloat(gasCost).toFixed(6)} MATIC`);
            return { success: true };
        } else {
            return { success: false, error: 'Transaction reverted' };
        }
    } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        return { success: false, error: errorMessage };
    }
};

const loadPositions = async (address: string): Promise<Position[]> => {
    const url = `https://data-api.polymarket.com/positions?user=${address}`;
    const data = await fetchData(url);
    const positions = Array.isArray(data) ? (data as Position[]) : [];
    return positions.filter((pos) => (pos.size || 0) > ZERO_THRESHOLD);
};

/**
 * Resolve a single position - try sell first, fallback to redeem
 */
const resolvePosition = async (
    clobClient: ClobClient,
    position: Position
): Promise<ResolveResult> => {
    const isWin = position.curPrice >= RESOLVED_HIGH;

    // First, try to sell via CLOB
    const sellResult = await trySellPosition(clobClient, position);

    if (sellResult.sold > 0) {
        return { method: 'sell', tokens: sellResult.sold, proceeds: sellResult.proceeds };
    }

    // If orderbook not available and position is redeemable, try on-chain redeem
    if (!sellResult.orderbookAvailable && position.redeemable) {
        Logger.info(`   📦 Orderbook closed, trying on-chain redeem...`);

        const redeemResult = await redeemPosition(position);

        if (redeemResult.success) {
            // For wins, proceeds = token amount (each token redeems for $1)
            // For losses, proceeds = 0
            const proceeds = isWin ? position.size : 0;
            return { method: 'redeem', tokens: position.size, proceeds };
        } else {
            Logger.error(`   ❌ Redeem failed: ${redeemResult.error}`);
        }
    } else if (!sellResult.orderbookAvailable && !position.redeemable) {
        Logger.warning(`   ⏳ Orderbook closed but market not yet redeemable`);
    }

    return { method: 'failed', tokens: 0, proceeds: 0 };
};

const checkAndResolvePositions = async (clobClient: ClobClient): Promise<void> => {
    const allPositions = await loadPositions(PROXY_WALLET);

    if (allPositions.length === 0) {
        return;
    }

    // Filter for resolved positions (price >= 99% or <= 1%)
    const resolvedPositions = allPositions.filter(
        (pos) => pos.curPrice >= RESOLVED_HIGH || pos.curPrice <= RESOLVED_LOW
    );

    if (resolvedPositions.length === 0) {
        return;
    }

    Logger.header(`🔄 AUTO-RESOLVE: Found ${resolvedPositions.length} resolved position(s)`);

    let totalSold = 0;
    let totalRedeemed = 0;
    let totalProceeds = 0;

    // Group positions by conditionId for redeem (redeem handles all outcomes at once)
    const processedConditions = new Set<string>();

    for (const position of resolvedPositions) {
        const status = position.curPrice >= RESOLVED_HIGH ? '🎉 WIN' : '❌ LOSS';
        Logger.info(`${status} | ${position.title || position.slug || position.asset}`);
        if (position.outcome) {
            Logger.info(`   Outcome: ${position.outcome}`);
        }
        Logger.info(
            `   Size: ${position.size.toFixed(2)} tokens @ avg $${position.avgPrice.toFixed(3)}`
        );
        Logger.info(
            `   Price: $${position.curPrice.toFixed(4)} | Value: $${position.currentValue.toFixed(2)} | Redeemable: ${position.redeemable ? 'Yes' : 'No'}`
        );

        // Skip if we already redeemed this condition
        if (processedConditions.has(position.conditionId)) {
            Logger.info(`   ⏭️  Already processed this condition`);
            continue;
        }

        try {
            const result = await resolvePosition(clobClient, position);

            if (result.method === 'sell') {
                totalSold += result.tokens;
                totalProceeds += result.proceeds;
            } else if (result.method === 'redeem') {
                totalRedeemed += result.tokens;
                totalProceeds += result.proceeds;
                processedConditions.add(position.conditionId);
            }
        } catch (error) {
            Logger.error(`   ❌ Failed to resolve: ${error}`);
        }
    }

    if (totalSold > 0 || totalRedeemed > 0) {
        Logger.success(`AUTO-RESOLVE Complete:`);
        if (totalSold > 0) {
            Logger.info(`   Sold via CLOB: ${totalSold.toFixed(2)} tokens`);
        }
        if (totalRedeemed > 0) {
            Logger.info(`   Redeemed on-chain: ${totalRedeemed.toFixed(2)} tokens`);
        }
        Logger.info(`   Total proceeds: ~$${totalProceeds.toFixed(2)}`);
    }
    Logger.separator();
};

const autoResolver = async (clobClient: ClobClient) => {
    if (!AUTO_RESOLVE_ENABLED) {
        Logger.info('Auto resolver is disabled');
        return;
    }

    Logger.success(`Auto resolver started (checking every ${AUTO_RESOLVE_INTERVAL}s)`);
    Logger.info(`   Thresholds: WIN >= $${RESOLVED_HIGH}, LOSS <= $${RESOLVED_LOW}`);
    Logger.info(`   Fallback: On-chain redeem if orderbook closed`);

    while (isRunning) {
        try {
            await checkAndResolvePositions(clobClient);
        } catch (error) {
            Logger.error(`Auto resolver error: ${error}`);
        }

        if (!isRunning) break;
        await new Promise((resolve) => setTimeout(resolve, AUTO_RESOLVE_INTERVAL * 1000));
    }

    Logger.info('Auto resolver stopped');
};

export default autoResolver;
