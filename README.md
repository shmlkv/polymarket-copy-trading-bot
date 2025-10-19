# Polymarket Copy Trading Bot

## Introduction

This project is a Polymarket Copy Trading Bot that allows users to automatically copy trades from selected traders on Polymarket.

![Polymarket Copy Trading Bot](./docs/screenshot.png)

Check user performance [on Predictfolio](https://predictfolio.com/dashboard/0x7c3db723f1d4d8cb9c550095203b686cb11e5c6b).

## Features

- **Multi-Trader Support**: Track and copy trades from multiple traders simultaneously
- **Automated Trading**: Automatically copy trades with proportional position sizing
- **Real-time Monitoring**: Continuously monitor selected traders' activity
- **Beautiful Logging**: Clean, colorful console output with structured information
- **Customizable Settings**: Configure trading parameters and risk management
- **Flexible Configuration**: Support for comma-separated or JSON array of trader addresses
- **Secure**: No credential exposure in logs

## Installation

1. Install latest version of Node.js and npm
2. Navigate to the project directory:
    ```bash
    cd polymarket_copy_trading_bot
    ```
3. Create `.env` file from example:
    ```bash
    cp .env.example .env
    ```
4. Configure env variables in `.env`:

    ```bash
    # Single trader
    USER_ADDRESSES = '0xTrader1Address...'

    # OR Multiple traders (comma-separated)
    USER_ADDRESSES = '0xTrader1..., 0xTrader2..., 0xTrader3...'

    # OR Multiple traders (JSON array)
    USER_ADDRESSES = '["0xTrader1...", "0xTrader2...", "0xTrader3..."]'

    PROXY_WALLET = 'Your Polygon wallet address'
    PRIVATE_KEY = 'Your wallet private key (without 0x)'

    CLOB_HTTP_URL = 'https://clob.polymarket.com/'
    CLOB_WS_URL = 'wss://ws-subscriptions-clob.polymarket.com/ws'

    FETCH_INTERVAL = 1      # Check for new trades every N seconds
    TOO_OLD_TIMESTAMP = 1   # Ignore trades older than N hours
    RETRY_LIMIT = 3         # Retry failed orders N times

    MONGO_URI = 'your_mongodb_connection_string'
    RPC_URL = 'your_polygon_rpc_url'
    USDC_CONTRACT_ADDRESS = '0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174'
    ```

    **Security Warning**: Never commit your `.env` file or share your `PRIVATE_KEY` and `MONGO_URI`!

5. Install the required dependencies:
    ```bash
    npm install
    ```
6. Build the project:
    ```bash
    npm run build
    ```
7. Run BOT:
    ```bash
    npm run start
    ```

## Contributing

Contributions are welcome! Please open an issue or submit a pull request. And if you are interested in this project, please consider giving it a star✨.

<!--
## Contact

For updated version or any questions, please contact me at [Telegram](https://t.me/trust4120). -->
