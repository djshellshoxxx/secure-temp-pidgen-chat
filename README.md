# Secure Temp Chat

A static web app (GitHub Pages) for short-lived, end-to-end encrypted chats over **IRC** and **XMPP**
(and **SILC / GroupWise through a gateway you run**), with a live report of every encryption layer in use,
an **encryption score** and a **privacy score**, optional **Tor / I2P** routing, and optional **one-time pads**.

Nothing is stored: keys, pads, passwords and messages live in the tab's memory only. "Burn" wipes them.

## What is and isn't possible (honest version)

| Network | Directly from the page | Via the local bridge |
|---|---|---|
| IRC | Only servers that offer a WebSocket (`wss://`) | **Any** IRC server on its TLS port, plus Tor / I2P |
| XMPP | Servers with the WebSocket module (RFC 7395) | Any such server, plus Tor / I2P |
| SILC | Impossible (no browser can speak SILC) | Through your own IRC-style gateway (e.g. BitlBee/libpurple). **Untested.** |
| GroupWise | Impossible | Same, **untested** |

Other honest limits:

* A web page **cannot read the negotiated TLS version/cipher** and **cannot route itself through Tor/I2P**.
  The bridge can do both, so with it the report shows the *real* cipher and certificate status.
* The end-to-end layer is **Signal-style / OTR-like, not compatible** with Signal, OTR or OMEMO clients.
  Both people must use this page. It has had no independent audit.
* TLS **client certificates** are handled by the browser; the page can't see or use them, so they are not scored.

## About authentication and perfect forward secrecy

Authentication does **not** automatically destroy forward secrecy. What matters is whether the long-term secret derives the message keys:

| Setup | PFS | Deniable |
|---|---|---|
| Ephemeral key exchange, compare 8-digit code | yes | yes |
| Ephemeral exchange + **signed** with identity key | **yes** | **no** (signatures prove you took part) |
| Ephemeral exchange + shared secret mixed in | yes | yes |
| **Static long-term keys** (certificate-style) | **no** | mostly |
| Passphrase only | **no** | yes |
| One-time pad | depends on pad handling | yes |

The report states which case you are in.

## Encryption modes

* **Double Ratchet** - AES-256-GCM, ECDH (P-256 / P-384 / X25519), HKDF-SHA-256. PFS per message + post-compromise security.
* **Session ECDH** - same primitives, one ephemeral exchange per session, one-way key chain.
* **Static keys** - no PFS (shown as such).
* **Passphrase** - PBKDF2-SHA-256 (600k rounds) + AES-256-GCM; also works in channels.
* **One-time pad** - XOR + HMAC-SHA-256 tag from fresh pad bytes; used pad bytes are zeroed.
* Handshake is protected against SAS grinding with a hash commitment; message lengths are padded to 64 bytes.

## Deploy on GitHub Pages (step by step)

1. Push this repository to GitHub (the files are already at the repository root).
2. On GitHub: **Settings -> Pages**.
3. Under **Build and deployment**, set **Source** = *Deploy from a branch*, **Branch** = `main`, folder = `/ (root)`, press **Save**.
4. Wait about a minute. Your site is `https://YOURNAME.github.io/secure-temp-pidgen-chat/`.

## Run the local bridge (Tor / I2P / any IRC server / real TLS cipher)

The page builds the exact command for you (step 3 in the page -> "Install & start the bridge"). Manually:

```bash
node gateway/stc-bridge.cjs --origin https://YOURNAME.github.io
# optional: --tor 127.0.0.1:9050  --i2p 127.0.0.1:4447  --allow-insecure-tls  --allow-host irc.example.org
```

Safety: it listens on 127.0.0.1 only, accepts **only** the page origins you pass with `--origin`, and only uses the Tor/I2P
SOCKS ports you configured. Do not expose it to a network. Chrome and Firefox allow `ws://127.0.0.1` from an https page; Safari may not.

## Develop / test

```bash
npm test                 # 38 tests: crypto, scoring, SCRAM vector, IRC/XMPP mocks, bridge incl. TLS + SOCKS
npx http-server -p 8080 .
```
