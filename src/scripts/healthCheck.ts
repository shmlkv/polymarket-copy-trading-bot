import * as dotenv from 'dotenv';
dotenv.config();

import connectDB, { closeDB } from '../config/db';
import { performHealthCheck, logHealthCheck } from '../utils/healthCheck';

const main = async () => {
    try {
        await connectDB();
        const result = await performHealthCheck();
        logHealthCheck(result);

        if (result.healthy) {
            console.log('\n✅ All systems operational');
            process.exit(0);
        } else {
            console.log('\n❌ Some health checks failed');
            process.exit(1);
        }
    } catch (error) {
        console.error('Error performing health check:', error);
        process.exit(1);
    } finally {
        await closeDB();
    }
};

main();

