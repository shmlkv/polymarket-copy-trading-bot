# 💰 How to Fund Your Trading Wallet with USDC

Your bot needs USDC (USD Coin) on the **Polygon network** to copy trades.

## Your Wallet Address
```
0x4fbBe5599c06e846D2742014c9eB04A8a3d1DE8C
```

## Step-by-Step Guide

### Option 1: Direct Bridge (Recommended)

1. **Get USDC on Polygon**
   - Visit [Polygon Bridge](https://wallet.polygon.technology/polygon/bridge/deposit)
   - Connect your wallet (MetaMask recommended)
   - Select "USDC" from the token list
   - Choose "Polygon PoS" network
   - Enter amount and bridge

2. **Or Use a Centralized Exchange**
   - **Binance**: Withdraw USDC → Select "Polygon" network → Paste your address
   - **Coinbase**: Transfer USDC → Select "Polygon" → Send to your address
   - **KuCoin**: Withdraw USDC → Choose "Polygon" → Enter address

### Option 2: Buy Directly on Polygon

1. **Use a Fiat On-Ramp**
   - [Transak](https://global.transak.com/) - Buy USDC directly on Polygon
   - [Ramp Network](https://ramp.network/) - Credit/Debit card purchases
   - [MoonPay](https://www.moonpay.com/) - Global fiat gateway

### Important Notes

✅ **Network**: Must be **Polygon (MATIC)**, not Ethereum mainnet
✅ **Token**: Native USDC contract: `0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359`
✅ **Gas**: Also keep ~$5-10 worth of MATIC for transaction fees

**Note on USDC Contracts:**
- **Native USDC** (recommended): `0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359` - Used by most exchanges
- **Bridged USDC.e** (old): `0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174` - Legacy bridged version

The bot is configured to use **Native USDC**. If you have USDC.e, you can swap it to native USDC on [Uniswap](https://app.uniswap.org/).

⚠️ **Warning**: Sending USDC on the wrong network (like Ethereum) will result in loss of funds!

## Verify Your Balance

After funding, check your balance:

```bash
# Using Polygonscan
https://polygonscan.com/address/0x4fbBe5599c06e846D2742014c9eB04A8a3d1DE8C

# Or restart the bot - it will show your balance
npm start
```

## Minimum Recommended Amount

- **Testing**: $50-100 USDC
- **Small trading**: $500-1,000 USDC
- **Serious copying**: $2,000+ USDC

Remember: The bot calculates trade sizes proportionally based on your balance vs. the trader's balance.

## Example

If you have $1,000 and copy a trader with $100,000:
- Trader buys $5,000 worth → You buy ~$50 worth (1:20 ratio)
- Trader sells 50% → You sell 50%

---

**Ready?** Once funded, restart the bot and it will start copying trades automatically! 🚀
