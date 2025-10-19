import mongoose from 'mongoose';
import { ENV } from './env';
import chalk from 'chalk';

const uri = ENV.MONGO_URI || 'mongodb://localhost:27017/polymarket_copytrading';

const connectDB = async () => {
    try {
        await mongoose.connect(uri);
        console.log(chalk.green('✓'), 'MongoDB connected');
    } catch (error) {
        console.log(chalk.red('✗'), 'MongoDB connection failed:', error);
        process.exit(1);
    }
};

export default connectDB;
