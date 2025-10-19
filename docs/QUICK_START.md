# 🚀 Quick Start Guide

## Prerequisites

- Node.js v18+ installed
- MongoDB database (Atlas or local)
- Polygon wallet with USDC
- Some MATIC for gas fees

## Setup (5 minutes)

### 1. Configure Environment

Edit `.env` file:

```bash
# Single trader
USER_ADDRESSES = '0x7c3db723f1d4d8cb9c550095203b686cb11e5c6b'

# OR multiple traders
USER_ADDRESSES = '0xTrader1..., 0xTrader2..., 0xTrader3...'

# Your wallet
PROXY_WALLET = '0xYourWalletAddress'
PRIVATE_KEY = 'your_private_key_without_0x'

# MongoDB
MONGO_URI = 'mongodb+srv://username:password@cluster.mongodb.net/database'

# Polygon RPC (get from Infura/Alchemy)
RPC_URL = 'https://polygon-mainnet.infura.io/v3/YOUR_KEY'
```

### 2. Install Dependencies

```bash
npm install
```

### 3. Build

```bash
npm run build
```

### 4. Run

```bash
npm start
```

## Expected Output

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  🤖 POLYMARKET COPY TRADING BOT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📊 Tracking 3 trader(s):
   1. 0x7c3db723f1d4d8cb9c550095203b686cb11e5c6b
   2. 0x6bab41a0dc40d6dd4c1a915b8c01969479fd1292
   3. 0xd218e474776403a330142299f7796e8ba32eb5c9

💼 Your Wallet:
   0x4fbBe5599c06e846D2742014c9eB04A8a3d1DE8C

✓ MongoDB connected
ℹ Initializing CLOB client...
✓ CLOB client ready
──────────────────────────────────────────────────────────────────────
📦 Database Status:
   0x7c3d...6b: 15 trades
   0x6bab...92: 8 trades
   0xd218...c9: 0 trades

✓ Monitoring 3 trader(s) every 1s
──────────────────────────────────────────────────────────────────────
[14:23:45] ⏳ Waiting for trades from 3 trader(s)...
```

## Finding Traders to Copy

1. Visit https://polymarket.com/leaderboard
2. Look for traders with:
   - Consistent profits (green P&L)
   - High win rate (>55%)
   - Active recent trading
   - Position sizes you can afford to copy

3. Copy their wallet address
4. Add to `USER_ADDRESSES` in `.env`

## Safety Tips

✅ **DO:**
- Start with small amounts
- Use a dedicated wallet
- Monitor bot regularly
- Track 3-5 different traders for diversification

❌ **DON'T:**
- Use your main wallet
- Store all funds in the bot wallet
- Copy traders blindly
- Leave bot running unattended for long periods

## Troubleshooting

### Bot doesn't start
```bash
# Check Node.js version
node --version  # Should be 18+

# Rebuild
rm -rf dist node_modules
npm install
npm run build
```

### MongoDB connection fails
- Verify `MONGO_URI` is correct
- Check MongoDB Atlas IP whitelist (allow all: 0.0.0.0/0)
- Test connection at https://mongodbcompass.com

### No trades detected
- Verify trader addresses are correct
- Check traders are actively trading
- Increase `FETCH_INTERVAL` to 2-3 seconds

### Trades failing
- Ensure `PROXY_WALLET` has USDC balance
- Ensure you have MATIC for gas (~$5-10 worth)
- Check `RPC_URL` is working

## What Happens When a Trade is Detected?

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ⚡ 1 NEW TRADE TO COPY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

──────────────────────────────────────────────────────────────────────
📊 NEW TRADE DETECTED
Trader: 0x7c3d...6b
Side:   BUY
Amount: $150
Price:  0.68
──────────────────────────────────────────────────────────────────────

Balances:
  Your balance:   $1000.00
  Trader balance: $15000.00 (0x7c3d...6b)

ℹ Executing BUY strategy...
ℹ Position ratio: 9.1%
ℹ Best ask: 100 @ $0.685
✓ Order executed: Sold 21.8 tokens at $0.685
```

The bot:
1. Detects the trade
2. Calculates your proportional position size
3. Finds best price in order book
4. Executes the order
5. Updates database

## Position Size Calculation

```
ratio = your_balance / (trader_balance + trade_size)
your_trade = trader_trade_size × ratio
```

**Example:**
- Your balance: $1,000
- Trader balance: $10,000
- Trader buys: $500

```
ratio = 1,000 / (10,000 + 500) = 0.095 (9.5%)
You buy: $500 × 0.095 = $47.50
```

## Stopping the Bot

Press `Ctrl + C` to stop gracefully.

## Need Help?

- Read full documentation: `MULTI_TRADER_GUIDE.md`
- See logging examples: `LOGGING_PREVIEW.md`
- Contact: https://t.me/trust4120
- Issues: GitHub Issues

## Next Steps

Once running successfully:
1. Monitor for 24 hours with small amounts
2. Review trade execution accuracy
3. Adjust `FETCH_INTERVAL` if needed
4. Scale up gradually
5. Consider adding protective limits (see feature roadmap)

Good luck! 🚀
