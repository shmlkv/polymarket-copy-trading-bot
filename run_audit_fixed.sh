#!/bin/bash
cd /Users/sh/code/polymarket-copy-trading-bot-v1

export AUDIT_DAYS=14
export AUDIT_MULTIPLIER=1.0
export AUDIT_STARTING_CAPITAL=1000
export COPY_PERCENTAGE=1.0  # Copy 1% of trader's order size

/usr/local/bin/node ./node_modules/.bin/ts-node src/scripts/auditCopyTradingAlgorithmFixed.ts
