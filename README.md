# IRC Client

A feature-rich terminal-based IRC client with SASL authentication, message logging, and advanced flood protection.

## Features

- **Secure Connections**: Supports SSL/TLS encrypted connections
- **SASL Authentication**: PLAIN and EXTERNAL (certificate) authentication methods
- **Message Logging**: Per-channel logging with daily rotation
- **Flood Protection**: Automatic user blocking on flood detection
- **Auto-Reconnect**: Automatic reconnection with channel rejoining
- **CTCP Handling**: Version response and DCC blocking
- **Terminal UI**: Curses-based interface with message history

## Installation

1. Ensure Python 3.6+ is installed
2. Install required dependencies:
   ```bash
   pip install cryptography
   ```

3. Run the client:
   ```bash
   python irc-client.py
   ```

## Commands

### Connection Commands

- /join <channel> - Join specified channel
- /part [channel] [message] - Leave channel with optional message
- /quit [message] - Disconnect from server (default: "Goodbye!")
- /nick <newnick> - Change nickname

### Messaging Commands

- /msg <target> <message> - Send private message to user/channel
- /me <message> - Send action message to current channel
- /list - Show message history for all channels/users
- /switch <target> - Switch active conversation

## Message Handling

- Private Messages: Marked with [PM] prefix and displayed in uppercase
- Channel Messages: Prefixed with channel name ([#channel])
- Mentions: Messages containing your nick are uppercased
- CTCP: Only responds to VERSION requests
- Flood Control: Users sending >3 messages in 10s are blocked for 24h

## Configuration

Client settings are stored in irc_client_config.json in the current directory, including:

- Server connection details
- SASL credentials
- Certificate paths
- Channel autojoin list
- Logging preferences

## Security

- Configuration files are stored with 600 permissions
- SASL PLAIN authentication uses base64-encoded credentials
- EXTERNAL authentication requires client certificate
- All CTCP/DCC requests except VERSION are blocked

## Keybindings

- Page Up/Down - Scroll through message history
- Home/End - Jump to start/end of history
- Up/Down - Navigate command history
- Left/Right - Move cursor in input field
- Ctrl+C - Quit client

## License

MIT License - [View License](https://github.com/IRC-Client/irc-client/blob/main/LICENSE)
