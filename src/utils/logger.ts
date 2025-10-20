import chalk from 'chalk';

class Logger {
    private static formatAddress(address: string): string {
        return `${address.slice(0, 6)}...${address.slice(-4)}`;
    }

    private static maskAddress(address: string): string {
        // Show 0x and first 4 chars, mask middle, show last 4 chars
        return `${address.slice(0, 6)}${'*'.repeat(34)}${address.slice(-4)}`;
    }

    static header(title: string) {
        console.log('\n' + chalk.cyan('━'.repeat(70)));
        console.log(chalk.cyan.bold(`  ${title}`));
        console.log(chalk.cyan('━'.repeat(70)) + '\n');
    }

    static info(message: string) {
        console.log(chalk.blue('ℹ'), message);
    }

    static success(message: string) {
        console.log(chalk.green('✓'), message);
    }

    static warning(message: string) {
        console.log(chalk.yellow('⚠'), message);
    }

    static error(message: string) {
        console.log(chalk.red('✗'), message);
    }

    static trade(traderAddress: string, action: string, details: any) {
        console.log('\n' + chalk.magenta('─'.repeat(70)));
        console.log(chalk.magenta.bold('📊 NEW TRADE DETECTED'));
        console.log(chalk.gray(`Trader: ${this.formatAddress(traderAddress)}`));
        console.log(chalk.gray(`Action: ${chalk.white.bold(action)}`));
        if (details.asset) {
            console.log(chalk.gray(`Asset:  ${this.formatAddress(details.asset)}`));
        }
        if (details.side) {
            const sideColor = details.side === 'BUY' ? chalk.green : chalk.red;
            console.log(chalk.gray(`Side:   ${sideColor.bold(details.side)}`));
        }
        if (details.amount) {
            console.log(chalk.gray(`Amount: ${chalk.yellow(`$${details.amount}`)}`));
        }
        if (details.price) {
            console.log(chalk.gray(`Price:  ${chalk.cyan(details.price)}`));
        }
        if (details.eventSlug || details.slug) {
            // Use eventSlug for the correct market URL format
            const slug = details.eventSlug || details.slug;
            const marketUrl = `https://polymarket.com/event/${slug}`;
            console.log(chalk.gray(`Market: ${chalk.blue.underline(marketUrl)}`));
        }
        if (details.transactionHash) {
            const txUrl = `https://polygonscan.com/tx/${details.transactionHash}`;
            console.log(chalk.gray(`TX:     ${chalk.blue.underline(txUrl)}`));
        }
        console.log(chalk.magenta('─'.repeat(70)) + '\n');
    }

    static balance(myBalance: number, traderBalance: number, traderAddress: string) {
        console.log(chalk.gray('Balances:'));
        console.log(chalk.gray(`  Your balance:   ${chalk.green.bold(`$${myBalance.toFixed(2)}`)}`));
        console.log(
            chalk.gray(`  Trader balance: ${chalk.blue.bold(`$${traderBalance.toFixed(2)}`)} (${this.formatAddress(traderAddress)})`)
        );
    }

    static orderResult(success: boolean, message: string) {
        if (success) {
            console.log(chalk.green('✓'), chalk.green.bold('Order executed:'), message);
        } else {
            console.log(chalk.red('✗'), chalk.red.bold('Order failed:'), message);
        }
    }

    static monitoring(traderCount: number) {
        const timestamp = new Date().toLocaleTimeString();
        console.log(chalk.dim(`[${timestamp}]`), chalk.cyan('👁️  Monitoring'), chalk.yellow(`${traderCount} trader(s)`));
    }

    static startup(traders: string[], myWallet: string) {
        console.log('\n');
        // ASCII Art Logo with gradient colors
        console.log(chalk.cyan('  ____       _        ____                 '));
        console.log(chalk.cyan(' |  _ \\ ___ | |_   _ / ___|___  _ __  _   _ '));
        console.log(chalk.cyan.bold(' | |_) / _ \\| | | | | |   / _ \\| \'_ \\| | | |'));
        console.log(chalk.magenta.bold(' |  __/ (_) | | |_| | |__| (_) | |_) | |_| |'));
        console.log(chalk.magenta(' |_|   \\___/|_|\\__, |\\____\\___/| .__/ \\__, |'));
        console.log(chalk.magenta('               |___/            |_|    |___/ '));
        console.log(chalk.gray('               Copy the best, automate success\n'));

        console.log(chalk.cyan('━'.repeat(70)));
        console.log(chalk.cyan('📊 Tracking Traders:'));
        traders.forEach((address, index) => {
            console.log(chalk.gray(`   ${index + 1}. ${address}`));
        });
        console.log(chalk.cyan(`\n💼 Your Wallet:`));
        console.log(chalk.gray(`   ${this.maskAddress(myWallet)}\n`));
    }

    static dbConnection(traders: string[], counts: number[]) {
        console.log(chalk.cyan('📦 Database Status:'));
        traders.forEach((address, index) => {
            const countStr = chalk.yellow(`${counts[index]} trades`);
            console.log(chalk.gray(`   ${this.formatAddress(address)}: ${countStr}`));
        });
        console.log('');
    }

    static separator() {
        console.log(chalk.dim('─'.repeat(70)));
    }

    private static spinnerFrames = ['⏳', '⌛', '⏳'];
    private static spinnerIndex = 0;

    static waiting(traderCount: number) {
        const timestamp = new Date().toLocaleTimeString();
        const spinner = this.spinnerFrames[this.spinnerIndex % this.spinnerFrames.length];
        this.spinnerIndex++;

        process.stdout.write(
            chalk.dim(`\r[${timestamp}] `) +
                chalk.cyan(`${spinner} Waiting for trades from `) +
                chalk.yellow(`${traderCount} trader(s)...`) +
                '  '
        );
    }

    static clearLine() {
        process.stdout.write('\r' + ' '.repeat(100) + '\r');
    }

    static positions(traders: string[], positionCounts: number[], positionDetails?: any[][]) {
        console.log(chalk.cyan('📈 Current Open Positions:'));
        traders.forEach((address, index) => {
            const count = positionCounts[index];
            const countStr = count > 0 ? chalk.green(`${count} position${count > 1 ? 's' : ''}`) : chalk.gray('0 positions');
            console.log(chalk.gray(`   ${this.formatAddress(address)}: ${countStr}`));

            // Show position details if available
            if (positionDetails && positionDetails[index] && positionDetails[index].length > 0) {
                positionDetails[index].forEach((pos: any) => {
                    const pnlColor = pos.percentPnl >= 0 ? chalk.green : chalk.red;
                    const pnlSign = pos.percentPnl >= 0 ? '+' : '';
                    console.log(chalk.gray(`      • ${pos.outcome} - ${pos.title.slice(0, 40)}${pos.title.length > 40 ? '...' : ''}`));
                    console.log(chalk.gray(`        Value: ${chalk.cyan(`$${pos.currentValue.toFixed(2)}`)} | PnL: ${pnlColor(`${pnlSign}${pos.percentPnl.toFixed(1)}%`)}`));
                });
            }
        });
        console.log('');
    }
}

export default Logger;
