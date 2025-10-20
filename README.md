# Polymarket Copy Trading Bot

> **Copy the best, automate success.** Mirror trades from top Polymarket traders with intelligent position sizing and real-time execution.

![Polymarket Copy Trading Bot](./docs/screenshot.png)

**Example trader:** Check performance on [Predictfolio](https://predictfolio.com/dashboard/0x7c3db723f1d4d8cb9c550095203b686cb11e5c6b)

## 🚀 Quick Start

**New to the bot?** Get started in 5 minutes with our [Quick Start Guide](./docs/QUICK_START.md).

Already familiar? Jump to [Installation](#installation) below.

---

## Overview

The Polymarket Copy Trading Bot automatically replicates trades from successful Polymarket traders to your wallet. Instead of manually tracking top performers, the bot monitors their activity 24/7 and executes proportionally sized trades on your behalf.

### How It Works

1. **Select Traders** - Choose top performers from [Polymarket leaderboard](https://polymarket.com/leaderboard) or [Predictfolio](https://predictfolio.com)
2. **Monitor Trades** - Bot continuously watches for new positions opened by your selected traders
3. **Calculate Position Size** - Automatically scales trades based on your balance vs. trader's balance
4. **Execute Orders** - Places matching orders on Polymarket using your wallet
5. **Track Performance** - Logs all activity and maintains trade history in MongoDB

### Position Sizing Example

If you're tracking a trader with $10,000 and they buy $500 worth of shares:
- Your balance: $1,000
- Position ratio: `$1,000 / ($10,000 + $500) = 9.5%`
- Base trade size: `$500 × 9.5% = $47.50`
- With 2x multiplier: `$47.50 × 2 = $95.00`

The bot ensures you maintain proportional exposure relative to the traders you follow, and you can amplify positions using the multiplier.

---

## Features

- **Multi-Trader Support** - Track and copy trades from multiple traders simultaneously
- **Smart Position Sizing** - Automatically adjusts trade sizes based on your capital
- **Real-time Execution** - Monitors trades every second and executes instantly
- **Beautiful Logging** - Clean, colorful console output with structured trade information
- **MongoDB Integration** - Persistent storage of all trades and positions
- **Flexible Configuration** - Support comma-separated or JSON array of trader addresses
- **Secure** - No credential exposure in logs, wallet addresses masked with `****`, private keys stay local
- **Price Protection** - Built-in slippage checks to avoid unfavorable fills

## Installation

### Prerequisites

- Node.js v18 or higher
- MongoDB database (MongoDB Atlas recommended)
- Polygon wallet with USDC balance
- Small amount of POL (formerly MATIC) for gas fees (~$5-10)

### Setup Steps

1. **Clone and Install**
   ```bash
   git clone <repository-url>
   cd polymarket-copy-trading-bot-v1
   npm install
   ```

2. **Configure Environment**
   ```bash
   cp .env.example .env
   ```

   Edit `.env` with your settings:
   ```bash
   # Traders to copy (comma-separated or JSON array)
   USER_ADDRESSES = '0x7c3db723f1d4d8cb9c550095203b686cb11e5c6b, 0x6bab41a0dc40d6dd4c1a915b8c01969479fd1292'

   # Your trading wallet
   PROXY_WALLET = 'your_polygon_wallet_address'
   PRIVATE_KEY = 'your_private_key_without_0x_prefix'

   # Database and RPC
   MONGO_URI = 'mongodb+srv://user:pass@cluster.mongodb.net/database'
   RPC_URL = 'https://polygon-mainnet.infura.io/v3/YOUR_PROJECT_ID'
   ```

3. **Build and Run**
   ```bash
   npm run build
   npm start
   ```

**📖 For detailed setup instructions, see the [Quick Start Guide](./docs/QUICK_START.md).**

---

## Configuration

### Finding Traders to Copy

1. Visit [Polymarket Leaderboard](https://polymarket.com/leaderboard)
2. Look for traders with:
   - Positive P&L (green)
   - Win rate above 55%
   - Active trading history
   - Position sizes you can afford to copy proportionally

3. Check their detailed stats on [Predictfolio](https://predictfolio.com)
4. Copy their wallet address and add to `USER_ADDRESSES`

### Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `USER_ADDRESSES` | Traders to copy (comma-separated or JSON) | `'0xABC..., 0xDEF...'` |
| `PROXY_WALLET` | Your Polygon wallet address | `'0x123...'` |
| `PRIVATE_KEY` | Your wallet private key (no 0x prefix) | `'abc123...'` |
| `FETCH_INTERVAL` | Check interval in seconds | `1` |
| `TRADE_MULTIPLIER` | Position size multiplier (default: 1.0) | `2.0` |
| `RETRY_LIMIT` | Maximum retry attempts for failed orders | `3` |
| `MONGO_URI` | MongoDB connection string | `'mongodb+srv://...'` |
| `RPC_URL` | Polygon RPC endpoint | `'https://polygon...'` |

### Trading Logic

**Buy Strategy:**
- Calculates position ratio: `your_balance / (trader_balance + trade_size)`
- Scales trade size proportionally to your capital
- Applies multiplier to final trade size
- Checks minimum order size ($1 minimum required by Polymarket)
- Checks price slippage (max $0.05 difference)
- Executes market order at best available price

**Sell Strategy:**
- Mirrors trader's sell percentage
- Applies multiplier to position sizing
- If trader sells 20% of position, bot sells 20% of yours (× multiplier)
- If trader closes entire position, bot closes yours completely

**Trade Multiplier:**

The `TRADE_MULTIPLIER` allows you to amplify or reduce your position sizes relative to the calculated ratio:
- `1.0` (default) - Exact proportional copying
- `2.0` - Double the position size (more aggressive)
- `0.5` - Half the position size (more conservative)

**Example:**
```
Trader (Balance: $50,000) buys $5,000 (10% of capital)
You (Balance: $1,000, Multiplier: 2.0)

Position ratio: 1,000 / 55,000 = 0.0182 (1.82%)
Base trade: $5,000 × 0.0182 = $91
With 2x multiplier: $91 × 2.0 = $182 (actual trade size)
```

⚠️ **Warning:** Higher multipliers increase both potential gains and losses. Use with caution!

---

## Safety and Risk Management

⚠️ **Important Disclaimers:**

- **Use at your own risk** - This bot executes real trades with real money
- **Start small** - Test with minimal funds before scaling up
- **Diversify** - Don't copy just one trader; track 3-5 different strategies
- **Monitor regularly** - Check bot logs daily to ensure proper execution
- **Set limits** - The current version has no built-in stop-loss or position limits
- **No guarantees** - Past performance of copied traders doesn't guarantee future results

### Best Practices

1. **Dedicated Wallet** - Use a separate wallet just for the bot, not your main funds
2. **Limited Capital** - Only allocate what you can afford to lose
3. **Research Traders** - Verify trader history and strategy before copying
4. **Active Monitoring** - Set up alerts and check the bot at least once daily
5. **Emergency Stop** - Know how to stop the bot quickly (Ctrl+C)

---

## Documentation

- **[Quick Start Guide](./docs/QUICK_START.md)** - Get running in 5 minutes
- **[Multi-Trader Guide](./docs/MULTI_TRADER_GUIDE.md)** - Advanced multi-trader setup
- **[Funding Guide](./docs/FUNDING_GUIDE.md)** - How to fund your wallet with USDC and POL
- **[Logging Preview](./docs/LOGGING_PREVIEW.md)** - See what the console output looks like

---

## Troubleshooting

### Common Issues

**Bot not detecting trades:**
- Verify trader addresses are correct
- Check that traders are actively trading
- Ensure MongoDB connection is stable

**Trades failing to execute:**
- Confirm USDC balance in `PROXY_WALLET`
- Verify you have MATIC for gas fees
- Check `RPC_URL` is responding (try pinging endpoint)

**Price slippage errors:**
- Current slippage tolerance is $0.05
- Markets may be moving too fast
- Consider increasing `FETCH_INTERVAL` to reduce race conditions

For more help, see the full troubleshooting section in [Quick Start Guide](./docs/QUICK_START.md).

---

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

If you find this project helpful, please consider giving it a star ✨

---

## License

This project is provided as-is for educational and research purposes. Users are responsible for compliance with local laws and Polymarket's terms of service.

---

## Acknowledgments

- Built on [Polymarket CLOB Client](https://github.com/Polymarket/clob-client)
- Uses [Predictfolio](https://predictfolio.com) for trader analytics
- Powered by Polygon network

---

**Disclaimer:** This software is for educational purposes only. Trading involves risk of loss. The developers are not responsible for any financial losses incurred while using this bot.
