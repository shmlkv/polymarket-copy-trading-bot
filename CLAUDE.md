# Development Notes for Claude

## Recent Changes

### Position Tracking System (2025-10-22)

**Problem:** When user tops up balance after buying a position, the bot would sell incorrect proportions because it calculated from current balance instead of actually purchased tokens.

**Solution:** Implemented position tracking system that remembers actual tokens bought and sells proportionally.

**Changes:**

- Added `myBoughtSize` field to `UserActivityInterface` and `activitySchema`
- Modified BUY logic: tracks total tokens bought and saves to `myBoughtSize`
- Modified SELL logic:
    - Loads previous BUY trades with `myBoughtSize`
    - Calculates sell amount from tracked purchases, not current position
    - Updates/clears `myBoughtSize` after successful sell
- Added documentation: `docs/POSITION_TRACKING.md`
- Updated README with new feature

**Key Benefits:**

- ✅ Correct proportional selling regardless of balance changes
- ✅ User can top up balance anytime without affecting sell logic
- ✅ Backward compatible (fallback to old logic if no tracking data)

**Logs to watch:**

```
Buy: 📝 Tracked purchase: X.XX tokens for future sell calculations
Sell: 📊 Found N previous purchases: X.XX tokens bought
Sell complete: 🧹 Cleared purchase tracking (100%) or 📝 Updated (partial)
```

## Architecture Notes

### Database Schema

- Uses separate MongoDB collections per trader: `user_activities_{address}` and `user_positions_{address}`
- Activity documents track both trader actions and bot execution state (`bot`, `botExcutedTime`, `myBoughtSize`)

### Trade Execution Flow

1. `tradeMonitor.ts` - Fetches trader activity from Polymarket API every N seconds
2. `tradeExecutor.ts` - Reads unprocessed trades from DB, executes them
3. `postOrder.ts` - Handles actual order placement logic (BUY/SELL/MERGE)

### Important Constants

- `MIN_ORDER_SIZE_USD = 1.0` - Polymarket minimum for BUY
- `MIN_ORDER_SIZE_TOKENS = 1.0` - Minimum for SELL/MERGE
- `TRADE_MULTIPLIER` - Config multiplier applied to position sizes

## Code Style

- Keep comments short and high-level
- Use only yarn (not npm)
- Never commit changes automatically
- Avoid running bots in terminal during development
- Use bash without # comments

## Testing Notes

- Simulation scripts in `src/scripts/` for backtesting
- Real trading requires funded wallet + MongoDB + Polymarket API access
