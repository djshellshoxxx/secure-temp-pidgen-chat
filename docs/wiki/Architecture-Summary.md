# Architecture Summary

From the README.

- **Static page, no storage.** Keys, pads, passwords and messages stay in memory. "Burn" wipes them (README).
- **Two reach modes.** Directly from the page (only servers that offer a WebSocket endpoint), or through the local bridge, which can reach any IRC server and add Tor or I2P routing and real cipher reporting (README table).
- **Own end-to-end layer.** It is Signal-style and OTR-like, but it is not compatible with Signal, OTR or OMEMO clients, so both people must use this page (README).
- **Honest limits.** A web page cannot read the negotiated TLS cipher or route through Tor or I2P; TLS client certificates are not scored (README).
- **Forward secrecy depends on key derivation.** The README table separates ephemeral exchange, signed exchange and pad-based designs (README "About authentication").
