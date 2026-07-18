# HexGuard

Telegram phishing detection daemon — monitors chat messages for suspicious links, homoglyphs, hidden URLs, and other threats.

## Architecture

```
Python Listener (MTProto)  →  gRPC  →  Rust Analyzer  →  Telegram Bot API (alerts)
```

- **Python**: Telethon MTProto listener reads messages from all chats
- **gRPC**: Internal communication on `127.0.0.1:50051`
- **Rust**: Analyzes messages, sends alerts via Bot API

## Prerequisites

- **Rust** (stable, edition 2024)
- **Python 3.12+** (built-in `tomllib`)
- Telegram bot token (create via [@BotFather](https://t.me/BotFather))
- Telegram API credentials (get at https://my.telegram.org)
- Telegram user account for MTProto listener

## Setup

### 1. Rust Analyzer

```bash
# Configure bot token and alert chat
nano config.toml
```

```toml
[bot]
token = "YOUR_BOT_TOKEN"
alert_chat_id = -1001234567890

[analysis]
alert_threshold = 50
queue_size = 1000

[filter]
blacklist_chats = []

[grpc]
listen_addr = "127.0.0.1:50051"
```

### 2. Python Listener

```bash
# Install dependencies
pip install -r python/requirements.txt

# Configure phone number
nano python/config.toml
```

```toml
[listener]
phone = "+79001234567"
api_id = 123456
api_hash = "your_api_hash_here"
session_dir = "session"

[filter]
blacklist_chats = []

[grpc]
server_addr = "127.0.0.1:50051"
```

## Running

### Terminal 1 — Rust gRPC Server

```bash
cargo run --release
```

### Terminal 2 — Python Listener

```bash
cd python
python listener.py
```

First run will:
1. Generate gRPC stubs automatically
2. Create Telethon session in `python/session/`
3. Prompt for SMS code and 2FA password if needed

If login fails, delete `python/session/` and retry.

## Configuration

### Alert Thresholds

| Score | Level | Action |
|-------|-------|--------|
| 0-49 | Low | Logged only |
| 50-79 | Suspicious | Bot alert |
| 80-100 | Critical | Bot alert |

### Blacklist

Add chat IDs to `blacklist_chats` in both config files to skip monitoring:

```toml
[filter]
blacklist_chats = [-1001111111111, -1002222222222]
```

Empty list = monitor all chats.

## Detection

- **Heuristic patterns**: known phishing keywords, urgency language
- **Hidden links**: zero-width characters, invisible URLs, dangerous schemes
- **Homoglyphs**: Cyrillic/Latin character substitution
- **URL tracing**: follows redirects, checks final destination
- **Unicode obfuscation**: normalization, skeleton comparison

## Graceful Shutdown

- **Rust**: `Ctrl+C` — stops server and worker
- **Python**: `Ctrl+C` — closes gRPC channel and Telethon session
