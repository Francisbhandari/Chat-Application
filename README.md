# Chat-Application

A terminal-based, encrypted one-on-one chat application built in C++ using raw POSIX sockets. The server handles user authentication, message persistence, and Caesar cipher encryption for stored messages.

---

## Features

- **User Authentication** — Register new users or log in with existing credentials
- **Encrypted Storage** — Messages and usernames are encrypted at rest using a Caesar cipher keyed from the user's password
- **Message History** — Returning users see their previous conversation on login
- **Persistent Users** — User credentials are saved across sessions
- **TCP Socket Communication** — Direct client-server communication over a configurable port

---

## Project Structure

```
.
├── server.cpp       # Full server source code
├── users.txt        # Stores registered usernames and hashed passwords (auto-created)
└── <username>.txt   # Per-user encrypted message logs (auto-created on first conversation)
```

---

## Requirements

- Linux / macOS (POSIX socket API)
- A C++ compiler with C++11 or later (e.g. `g++`)
- A TCP client (e.g. `telnet`, `nc`, or a custom client)

---

## Building

```bash
g++ -o server server.cpp
```

---

## Usage

### Starting the Server

```bash
./server <port>
```

**Example:**
```bash
./server 8080
```

### Connecting a Client

From another terminal (or machine):

```bash
nc <server-ip> <port>
# or
telnet <server-ip> <port>
```

---

## How It Works

### Authentication Flow

On connection, the client is prompted to choose:

```
New user or old user (new/old):
```

| Choice | Behaviour |
|--------|-----------|
| `new`  | Prompts for a username and password, registers the user, and starts a conversation |
| `old`  | Prompts for credentials, verifies against `users.txt`, loads message history |

### Conversation

- Both the server operator (via `stdin`) and the connected client can send messages in turn.
- Type `bye` on either side to end the session gracefully.

### Message Storage

After the conversation ends, all messages from the session are encrypted and appended to `<username>.txt`. On the next login, these are decrypted and displayed.

---

## Encryption

The `Crypt` class implements a **Caesar cipher**:

- The encryption key is derived by summing the ASCII values of the user's password.
- Both message content **and** sender usernames are encrypted before being written to disk.
- Decryption is applied when loading messages for a returning user.

> **Note:** Caesar cipher is a weak form of encryption and is not suitable for production or sensitive data. This implementation is intended for educational purposes.

---

## Known Limitations

- **Single client only** — The server handles one connection at a time; there is no multi-threading or `select`/`poll` loop.
- **Fixed buffer size** — The receive buffer is 100 bytes; messages longer than this will be truncated.
- **Plaintext credential file** — `users.txt` stores passwords as Caesar-encrypted strings, which is not cryptographically secure.
- **No TLS** — All network traffic is unencrypted in transit.
- **Sequential I/O** — The chat alternates turns strictly (server sends, client replies); free-form real-time messaging is not supported.

---

## Example Session

```
$ ./server 8080
Connection established with 127.0.0.1

New user or old user (new/old): new
Creating new

Enter username: alice
Enter password: secret
User Added Successfully
Registered Successfully

Enter bye to exit the conversation

Server: Hello, Alice!
alice: Hi there!

Server: bye
Server is disconnecting

Conversation ended
```
