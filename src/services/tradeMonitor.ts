import moment from 'moment';
import { ENV } from '../config/env';
import { UserActivityInterface, UserPositionInterface } from '../interfaces/User';
import { getUserActivityModel, getUserPositionModel } from '../models/userHistory';
import fetchData from '../utils/fetchData';
import Logger from '../utils/logger';

const USER_ADDRESSES = ENV.USER_ADDRESSES;
const TOO_OLD_TIMESTAMP = ENV.TOO_OLD_TIMESTAMP;
const FETCH_INTERVAL = ENV.FETCH_INTERVAL;

if (!USER_ADDRESSES || USER_ADDRESSES.length === 0) {
    throw new Error('USER_ADDRESSES is not defined or empty');
}

// Create activity and position models for each user
const userModels = USER_ADDRESSES.map((address) => ({
    address,
    UserActivity: getUserActivityModel(address),
    UserPosition: getUserPositionModel(address),
}));

const init = async () => {
    const counts: number[] = [];
    for (const { address, UserActivity } of userModels) {
        const count = await UserActivity.countDocuments();
        counts.push(count);
    }
    Logger.dbConnection(USER_ADDRESSES, counts);

    // Show current positions count with details
    const positionCounts: number[] = [];
    const positionDetails: any[][] = [];
    for (const { address, UserPosition } of userModels) {
        const positions = await UserPosition.find().exec();
        positionCounts.push(positions.length);

        // Get top 3 positions by current value
        const topPositions = positions
            .sort((a, b) => (b.currentValue || 0) - (a.currentValue || 0))
            .slice(0, 3)
            .map(p => p.toObject());
        positionDetails.push(topPositions);
    }
    Logger.positions(USER_ADDRESSES, positionCounts, positionDetails);
};

const fetchTradeData = async () => {
    for (const { address, UserActivity, UserPosition } of userModels) {
        try {
            // Fetch trade activities from Polymarket API
            const apiUrl = `https://data-api.polymarket.com/activity?user=${address}&type=TRADE`;
            const activities = await fetchData(apiUrl);

            if (!Array.isArray(activities) || activities.length === 0) {
                continue;
            }

            // Process each activity
            for (const activity of activities) {
                // Skip if too old
                if (activity.timestamp < TOO_OLD_TIMESTAMP) {
                    continue;
                }

                // Check if this trade already exists in database
                const existingActivity = await UserActivity.findOne({
                    transactionHash: activity.transactionHash,
                }).exec();

                if (existingActivity) {
                    continue; // Already processed this trade
                }

                // Save new trade to database
                const newActivity = new UserActivity({
                    proxyWallet: activity.proxyWallet,
                    timestamp: activity.timestamp,
                    conditionId: activity.conditionId,
                    type: activity.type,
                    size: activity.size,
                    usdcSize: activity.usdcSize,
                    transactionHash: activity.transactionHash,
                    price: activity.price,
                    asset: activity.asset,
                    side: activity.side,
                    outcomeIndex: activity.outcomeIndex,
                    title: activity.title,
                    slug: activity.slug,
                    icon: activity.icon,
                    eventSlug: activity.eventSlug,
                    outcome: activity.outcome,
                    name: activity.name,
                    pseudonym: activity.pseudonym,
                    bio: activity.bio,
                    profileImage: activity.profileImage,
                    profileImageOptimized: activity.profileImageOptimized,
                    bot: false,
                    botExcutedTime: 0,
                });

                await newActivity.save();
                Logger.info(`New trade detected for ${address.slice(0, 6)}...${address.slice(-4)}`);
            }

            // Also fetch and update positions
            const positionsUrl = `https://data-api.polymarket.com/positions?user=${address}`;
            const positions = await fetchData(positionsUrl);

            if (Array.isArray(positions) && positions.length > 0) {
                for (const position of positions) {
                    // Update or create position
                    await UserPosition.findOneAndUpdate(
                        { asset: position.asset, conditionId: position.conditionId },
                        {
                            proxyWallet: position.proxyWallet,
                            asset: position.asset,
                            conditionId: position.conditionId,
                            size: position.size,
                            avgPrice: position.avgPrice,
                            initialValue: position.initialValue,
                            currentValue: position.currentValue,
                            cashPnl: position.cashPnl,
                            percentPnl: position.percentPnl,
                            totalBought: position.totalBought,
                            realizedPnl: position.realizedPnl,
                            percentRealizedPnl: position.percentRealizedPnl,
                            curPrice: position.curPrice,
                            redeemable: position.redeemable,
                            mergeable: position.mergeable,
                            title: position.title,
                            slug: position.slug,
                            icon: position.icon,
                            eventSlug: position.eventSlug,
                            outcome: position.outcome,
                            outcomeIndex: position.outcomeIndex,
                            oppositeOutcome: position.oppositeOutcome,
                            oppositeAsset: position.oppositeAsset,
                            endDate: position.endDate,
                            negativeRisk: position.negativeRisk,
                        },
                        { upsert: true }
                    );
                }
            }
        } catch (error) {
            Logger.error(`Error fetching data for ${address.slice(0, 6)}...${address.slice(-4)}: ${error}`);
        }
    }
};

// Track if this is the first run
let isFirstRun = true;

const tradeMonitor = async () => {
    await init();
    Logger.success(`Monitoring ${USER_ADDRESSES.length} trader(s) every ${FETCH_INTERVAL}s`);
    Logger.separator();

    // On first run, mark all existing historical trades as already processed
    if (isFirstRun) {
        Logger.info('First run: marking all historical trades as processed...');
        for (const { address, UserActivity } of userModels) {
            const count = await UserActivity.updateMany(
                { bot: false },
                { $set: { bot: true, botExcutedTime: 999 } }
            );
            if (count.modifiedCount > 0) {
                Logger.info(`Marked ${count.modifiedCount} historical trades as processed for ${address.slice(0, 6)}...${address.slice(-4)}`);
            }
        }
        isFirstRun = false;
        Logger.success('Historical trades processed. Now monitoring for new trades only.');
        Logger.separator();
    }

    while (true) {
        await fetchTradeData();
        await new Promise((resolve) => setTimeout(resolve, FETCH_INTERVAL * 1000));
    }
};

export default tradeMonitor;
