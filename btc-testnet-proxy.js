#!/usr/bin/env node
// WS→SSL proxy for BTC testnet Electrum (Fulcrum)
// Bridges browser WebSocket to testnet.aranguren.org:51002 (SSL/TCP)

const { WebSocketServer } = require('ws');
const tls = require('tls');

const WS_PORT = 60003;
const TARGET_HOST = 'testnet.aranguren.org';
const TARGET_PORT = 51002;

const wss = new WebSocketServer({ port: WS_PORT });
console.log(`[proxy] WS listening on ws://localhost:${WS_PORT}`);
console.log(`[proxy] Forwarding to ${TARGET_HOST}:${TARGET_PORT} (SSL)`);

wss.on('connection', (ws, req) => {
  console.log(`[proxy] New browser connection from ${req.socket.remoteAddress}`);

  const sock = tls.connect(TARGET_PORT, TARGET_HOST, { rejectUnauthorized: false }, () => {
    console.log('[proxy] SSL connected to upstream');
  });

  let buf = '';
  sock.on('data', chunk => {
    buf += chunk.toString();
    // Electrum protocol: newline-delimited JSON
    let idx;
    while ((idx = buf.indexOf('\n')) !== -1) {
      const line = buf.slice(0, idx);
      buf = buf.slice(idx + 1);
      if (line.trim()) {
        ws.send(line);
      }
    }
  });

  ws.on('message', data => {
    const msg = data.toString();
    sock.write(msg + '\n');
  });

  ws.on('close', () => {
    console.log('[proxy] Browser disconnected');
    sock.destroy();
  });

  sock.on('error', err => {
    console.error('[proxy] Upstream error:', err.message);
    ws.close();
  });

  sock.on('close', () => {
    console.log('[proxy] Upstream closed');
    ws.close();
  });
});
