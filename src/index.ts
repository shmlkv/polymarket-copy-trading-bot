import connectDB from './config/db';
import { ENV } from './config/env';
import createClobClient from './utils/createClobClient';
import tradeExecutor from './services/tradeExecutor';
import tradeMonitor from './services/tradeMonitor';
import Logger from './utils/logger';
import test from './test/test';

const USER_ADDRESSES = ENV.USER_ADDRESSES;
const PROXY_WALLET = ENV.PROXY_WALLET;

export const main = async () => {
    await connectDB();
    Logger.startup(USER_ADDRESSES, PROXY_WALLET);

    Logger.info('Initializing CLOB client...');
    const clobClient = await createClobClient();
    Logger.success('CLOB client ready');

    Logger.separator();
    Logger.info('Starting trade monitor...');
    tradeMonitor();

    Logger.info('Starting trade executor...');
    tradeExecutor(clobClient);

    // test(clobClient);
};

main();
