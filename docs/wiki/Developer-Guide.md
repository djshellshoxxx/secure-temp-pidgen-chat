# Developer Guide

```sh
npm test      # node --test --test-force-exit tests/*.test.mjs: 38 tests, all pass on this snapshot
npm run serve # npx http-server on port 8080 (no cache)
```

The local bridge is `gateway/stc-bridge.cjs`. It runs the Tor and I2P routing, real TLS cipher reporting and a connection to any IRC server (README "Run the local bridge"). The bridge was not run in this pass.
