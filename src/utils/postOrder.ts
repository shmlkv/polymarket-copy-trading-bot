import { ClobClient, OrderType, Side } from '@polymarket/clob-client';
import { UserActivityInterface, UserPositionInterface } from '../interfaces/User';
import { getUserActivityModel } from '../models/userHistory';
import { ENV } from '../config/env';
import Logger from './logger';

const RETRY_LIMIT = ENV.RETRY_LIMIT;
const TRADE_MULTIPLIER = ENV.TRADE_MULTIPLIER;

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

const postOrder = async (
    clobClient: ClobClient,
    condition: string,
    my_position: UserPositionInterface | undefined,
    user_position: UserPositionInterface | undefined,
    trade: UserActivityInterface,
    my_balance: number,
    user_balance: number,
    userAddress: string
) => {
    const UserActivity = getUserActivityModel(userAddress);
    //Merge strategy
    if (condition === 'merge') {
        Logger.info('Executing MERGE strategy...');
        if (!my_position) {
            Logger.warning('No position to merge');
            await UserActivity.updateOne({ _id: trade._id }, { bot: true });
            return;
        }
        let remaining = my_position.size;

        // Check minimum order size
        const MIN_ORDER_SIZE = 1.0;
        if (remaining < MIN_ORDER_SIZE) {
            Logger.warning(`Position size (${remaining.toFixed(2)} tokens) too small to merge - skipping`);
            await UserActivity.updateOne({ _id: trade._id }, { bot: true });
            return;
        }

        let retry = 0;
        let abortDueToFunds = false;
        while (remaining > 0 && retry < RETRY_LIMIT) {
            const orderBook = await clobClient.getOrderBook(trade.asset);
            if (!orderBook.bids || orderBook.bids.length === 0) {
                Logger.warning('No bids available in order book');
                await UserActivity.updateOne({ _id: trade._id }, { bot: true });
                break;
            }

            const maxPriceBid = orderBook.bids.reduce((max, bid) => {
                return parseFloat(bid.price) > parseFloat(max.price) ? bid : max;
            }, orderBook.bids[0]);

            Logger.info(`Best bid: ${maxPriceBid.size} @ $${maxPriceBid.price}`);
            let order_arges;
            if (remaining <= parseFloat(maxPriceBid.size)) {
                order_arges = {
                    side: Side.SELL,
                    tokenID: my_position.asset,
                    amount: remaining,
                    price: parseFloat(maxPriceBid.price),
                };
            } else {
                order_arges = {
                    side: Side.SELL,
                    tokenID: my_position.asset,
                    amount: parseFloat(maxPriceBid.size),
                    price: parseFloat(maxPriceBid.price),
                };
            }
            // Order args logged internally
            const signedOrder = await clobClient.createMarketOrder(order_arges);
            const resp = await clobClient.postOrder(signedOrder, OrderType.FOK);
            if (resp.success === true) {
                retry = 0;
                Logger.orderResult(true, `Sold ${order_arges.amount} tokens at $${order_arges.price}`);
                remaining -= order_arges.amount;
            } else {
                const errorMessage = extractOrderError(resp);
                if (isInsufficientBalanceOrAllowanceError(errorMessage)) {
                    abortDueToFunds = true;
                    Logger.warning(`Order rejected: ${errorMessage || 'Insufficient balance or allowance'}`);
                    Logger.warning('Skipping remaining attempts. Top up funds or run `npm run check-allowance` before retrying.');
                    break;
                }
                retry += 1;
                Logger.warning(
                    `Order failed (attempt ${retry}/${RETRY_LIMIT})${errorMessage ? ` - ${errorMessage}` : ''}`
                );
            }
        }
        if (abortDueToFunds) {
            await UserActivity.updateOne({ _id: trade._id }, { bot: true, botExcutedTime: RETRY_LIMIT });
            return;
        }
        if (retry >= RETRY_LIMIT) {
            await UserActivity.updateOne({ _id: trade._id }, { bot: true, botExcutedTime: retry });
        } else {
            await UserActivity.updateOne({ _id: trade._id }, { bot: true });
        }
    } else if (condition === 'buy') {       //Buy strategy
        Logger.info('Executing BUY strategy...');
        const ratio = my_balance / (user_balance + trade.usdcSize);
        const balanceDiff = (user_balance + trade.usdcSize) / my_balance;

        Logger.info(
            `Balance comparison: You have $${my_balance.toFixed(2)} vs Trader's $${(user_balance + trade.usdcSize).toFixed(2)} (${balanceDiff.toFixed(1)}x larger)`
        );
        Logger.info(`Trader bought: $${trade.usdcSize.toFixed(2)}`);

        // Calculate base order size without multiplier
        let remaining = trade.usdcSize * ratio;
        Logger.info(
            `Proportional calculation: $${trade.usdcSize.toFixed(2)} × ${(ratio * 100).toFixed(3)}% = $${remaining.toFixed(4)}`
        );

        // Check minimum order size (Polymarket requires min $1)
        const MIN_ORDER_SIZE = 1.0;

        // Apply multiplier only if order is below minimum
        if (remaining < MIN_ORDER_SIZE) {
            const originalAmount = remaining;
            remaining = remaining * TRADE_MULTIPLIER;

            Logger.info(
                `Applying ${TRADE_MULTIPLIER}x multiplier (trade < $1): $${originalAmount.toFixed(4)} → $${remaining.toFixed(4)}`
            );

            // Check again after applying multiplier
            if (remaining < MIN_ORDER_SIZE) {
                Logger.warning(
                    `❌ Cannot execute: Final order size $${remaining.toFixed(4)} still below $1 minimum`
                );
                Logger.warning(
                    `💡 Solution: Need at least $${(MIN_ORDER_SIZE / TRADE_MULTIPLIER / ratio).toFixed(2)} balance to copy this $${trade.usdcSize.toFixed(2)} trade`
                );
                Logger.warning(
                    `   (Or trader needs to make larger trades, or reduce balance difference)`
                );
                await UserActivity.updateOne({ _id: trade._id }, { bot: true });
                return;
            }
        } else {
            Logger.info(
                `Order size: $${remaining.toFixed(2)} (already above $1, no multiplier needed)`
            );
        }

        // Check if we have enough available balance (leave 1% buffer for fees/rounding)
        const SAFETY_BUFFER = 0.99;
        if (remaining > my_balance * SAFETY_BUFFER) {
            Logger.warning(`Order size ($${remaining.toFixed(2)}) exceeds available balance ($${my_balance.toFixed(2)}) - reducing to fit`);
            remaining = my_balance * SAFETY_BUFFER;
            if (remaining < MIN_ORDER_SIZE) {
                Logger.warning(`Adjusted order size too small - skipping trade`);
                await UserActivity.updateOne({ _id: trade._id }, { bot: true });
                return;
            }
        }

        let retry = 0;
        let abortDueToFunds = false;
        while (remaining > 0 && retry < RETRY_LIMIT) {
            const orderBook = await clobClient.getOrderBook(trade.asset);
            if (!orderBook.asks || orderBook.asks.length === 0) {
                Logger.warning('No asks available in order book');
                await UserActivity.updateOne({ _id: trade._id }, { bot: true });
                break;
            }

            const minPriceAsk = orderBook.asks.reduce((min, ask) => {
                return parseFloat(ask.price) < parseFloat(min.price) ? ask : min;
            }, orderBook.asks[0]);

            Logger.info(`Best ask: ${minPriceAsk.size} @ $${minPriceAsk.price}`);
            if (parseFloat(minPriceAsk.price) - 0.05 > trade.price) {
                Logger.warning('Price slippage too high - skipping trade');
                await UserActivity.updateOne({ _id: trade._id }, { bot: true });
                break;
            }

            // Check if remaining amount is below minimum before creating order
            const MIN_ORDER_SIZE = 1.0;
            if (remaining < MIN_ORDER_SIZE) {
                Logger.info(`Remaining amount ($${remaining.toFixed(2)}) below minimum - completing trade`);
                await UserActivity.updateOne({ _id: trade._id }, { bot: true });
                break;
            }

            let order_arges;
            const maxOrderSize = parseFloat(minPriceAsk.size) * parseFloat(minPriceAsk.price);
            const orderSize = Math.min(remaining, maxOrderSize);

            // Additional safety check: ensure order size doesn't exceed balance
            if (orderSize > my_balance * 0.95) {
                Logger.warning(`Order size ($${orderSize.toFixed(2)}) too close to balance ($${my_balance.toFixed(2)}) - skipping`);
                await UserActivity.updateOne({ _id: trade._id }, { bot: true, botExcutedTime: RETRY_LIMIT });
                break;
            }

            order_arges = {
                side: Side.BUY,
                tokenID: trade.asset,
                amount: orderSize,
                price: parseFloat(minPriceAsk.price),
            };

            Logger.info(`Creating order: $${orderSize.toFixed(2)} @ $${minPriceAsk.price} (Balance: $${my_balance.toFixed(2)})`);
            // Order args logged internally
            const signedOrder = await clobClient.createMarketOrder(order_arges);
            const resp = await clobClient.postOrder(signedOrder, OrderType.FOK);
            if (resp.success === true) {
                retry = 0;
                Logger.orderResult(true, `Bought $${order_arges.amount.toFixed(2)} at $${order_arges.price}`);
                remaining -= order_arges.amount;
            } else {
                const errorMessage = extractOrderError(resp);
                if (isInsufficientBalanceOrAllowanceError(errorMessage)) {
                    abortDueToFunds = true;
                    Logger.warning(`Order rejected: ${errorMessage || 'Insufficient balance or allowance'}`);
                    Logger.warning('Skipping remaining attempts. Top up funds or run `npm run check-allowance` before retrying.');
                    break;
                }
                retry += 1;
                Logger.warning(
                    `Order failed (attempt ${retry}/${RETRY_LIMIT})${errorMessage ? ` - ${errorMessage}` : ''}`
                );
            }
        }
        if (abortDueToFunds) {
            await UserActivity.updateOne({ _id: trade._id }, { bot: true, botExcutedTime: RETRY_LIMIT });
            return;
        }
        if (retry >= RETRY_LIMIT) {
            await UserActivity.updateOne({ _id: trade._id }, { bot: true, botExcutedTime: retry });
        } else {
            await UserActivity.updateOne({ _id: trade._id }, { bot: true });
        }
    } else if (condition === 'sell') {
        //Sell strategy
        Logger.info('Executing SELL strategy...');
        let remaining = 0;
        if (!my_position) {
            Logger.warning('No position to sell');
            await UserActivity.updateOne({ _id: trade._id }, { bot: true });
            return;
        } else if (!user_position) {
            // Trader sold entire position - we sell entire position too
            remaining = my_position.size;
            Logger.info(
                `Trader closed entire position → Selling all your ${remaining.toFixed(2)} tokens`
            );
        } else {
            // Calculate the % of position the trader is selling
            const trader_sell_percent = trade.size / (user_position.size + trade.size);
            const trader_position_before = user_position.size + trade.size;

            Logger.info(
                `Position comparison: Trader has ${trader_position_before.toFixed(2)} tokens, You have ${my_position.size.toFixed(2)} tokens`
            );
            Logger.info(
                `Trader selling: ${trade.size.toFixed(2)} tokens (${(trader_sell_percent * 100).toFixed(2)}% of their position)`
            );

            // Apply same % to our position
            const baseSellSize = my_position.size * trader_sell_percent;
            Logger.info(
                `Your ${(trader_sell_percent * 100).toFixed(2)}% = ${baseSellSize.toFixed(2)} tokens`
            );

            // Apply multiplier symmetrically with BUY logic
            remaining = baseSellSize * TRADE_MULTIPLIER;

            if (TRADE_MULTIPLIER !== 1.0) {
                Logger.info(
                    `Applying ${TRADE_MULTIPLIER}x multiplier: ${baseSellSize.toFixed(2)} → ${remaining.toFixed(2)} tokens`
                );
            }
        }

        // Check minimum order size
        const MIN_ORDER_SIZE = 1.0;

        if (remaining < MIN_ORDER_SIZE) {
            Logger.warning(
                `❌ Cannot execute: Sell amount ${remaining.toFixed(2)} tokens below minimum (${MIN_ORDER_SIZE} token)`
            );
            Logger.warning(
                `💡 This happens when position sizes are too small or mismatched`
            );
            await UserActivity.updateOne({ _id: trade._id }, { bot: true });
            return;
        }

        // Cap sell amount to available position size
        if (remaining > my_position.size) {
            Logger.warning(
                `⚠️  Calculated sell ${remaining.toFixed(2)} tokens > Your position ${my_position.size.toFixed(2)} tokens`
            );
            Logger.warning(`Capping to maximum available: ${my_position.size.toFixed(2)} tokens`);
            remaining = my_position.size;
        }

        let retry = 0;
        let abortDueToFunds = false;
        while (remaining > 0 && retry < RETRY_LIMIT) {
            const orderBook = await clobClient.getOrderBook(trade.asset);
            if (!orderBook.bids || orderBook.bids.length === 0) {
                await UserActivity.updateOne({ _id: trade._id }, { bot: true });
                Logger.warning('No bids available in order book');
                break;
            }

            const maxPriceBid = orderBook.bids.reduce((max, bid) => {
                return parseFloat(bid.price) > parseFloat(max.price) ? bid : max;
            }, orderBook.bids[0]);

            Logger.info(`Best bid: ${maxPriceBid.size} @ $${maxPriceBid.price}`);
            let order_arges;
            if (remaining <= parseFloat(maxPriceBid.size)) {
                order_arges = {
                    side: Side.SELL,
                    tokenID: trade.asset,
                    amount: remaining,
                    price: parseFloat(maxPriceBid.price),
                };
            } else {
                order_arges = {
                    side: Side.SELL,
                    tokenID: trade.asset,
                    amount: parseFloat(maxPriceBid.size),
                    price: parseFloat(maxPriceBid.price),
                };
            }
            // Order args logged internally
            const signedOrder = await clobClient.createMarketOrder(order_arges);
            const resp = await clobClient.postOrder(signedOrder, OrderType.FOK);
            if (resp.success === true) {
                retry = 0;
                Logger.orderResult(true, `Sold ${order_arges.amount} tokens at $${order_arges.price}`);
                remaining -= order_arges.amount;
            } else {
                const errorMessage = extractOrderError(resp);
                if (isInsufficientBalanceOrAllowanceError(errorMessage)) {
                    abortDueToFunds = true;
                    Logger.warning(`Order rejected: ${errorMessage || 'Insufficient balance or allowance'}`);
                    Logger.warning('Skipping remaining attempts. Top up funds or run `npm run check-allowance` before retrying.');
                    break;
                }
                retry += 1;
                Logger.warning(
                    `Order failed (attempt ${retry}/${RETRY_LIMIT})${errorMessage ? ` - ${errorMessage}` : ''}`
                );
            }
        }
        if (abortDueToFunds) {
            await UserActivity.updateOne({ _id: trade._id }, { bot: true, botExcutedTime: RETRY_LIMIT });
            return;
        }
        if (retry >= RETRY_LIMIT) {
            await UserActivity.updateOne({ _id: trade._id }, { bot: true, botExcutedTime: retry });
        } else {
            await UserActivity.updateOne({ _id: trade._id }, { bot: true });
        }
    } else {
        Logger.error(`Unknown condition: ${condition}`);
    }
};

export default postOrder;
