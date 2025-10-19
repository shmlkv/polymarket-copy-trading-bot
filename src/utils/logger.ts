import chalk from 'chalk';

class Logger {
    private static formatAddress(address: string): string {
        return `${address.slice(0, 6)}...${address.slice(-4)}`;
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
        this.header('🤖 POLYMARKET COPY TRADING BOT');
        console.log(chalk.cyan('📊 Tracking Traders:'));
        traders.forEach((address, index) => {
            console.log(chalk.gray(`   ${index + 1}. ${address}`));
        });
        console.log(chalk.cyan(`\n💼 Your Wallet:`));
        console.log(chalk.gray(`   ${myWallet}\n`));
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

    static waiting(traderCount: number) {
        const timestamp = new Date().toLocaleTimeString();
        process.stdout.write(
            chalk.dim(`\r[${timestamp}] `) +
                chalk.cyan('⏳ Waiting for trades from ') +
                chalk.yellow(`${traderCount} trader(s)...`) +
                '  '
        );
    }

    static clearLine() {
        process.stdout.write('\r' + ' '.repeat(100) + '\r');
    }
}

export default Logger;
