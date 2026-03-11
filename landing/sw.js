// 0penw0rld Service Worker
const CACHE = '0penw0rld-v51';

const APP_SHELL = [
  '/',
  '/index.html',
  '/docs.html',
  '/shell.js',
  '/chat.html',
  '/mesh.html',
  '/wallet.html',
  '/id.html',
  '/pay.html',
  '/dex.html',
  '/loan.html',
  '/ledger.js',
  '/manifest.json',
  '/icons/icon-192.png',
  '/icons/icon-512.png',
  '/icons/icon-180.png',
];

// External APIs — always network-first
const NETWORK_FIRST = [
  'midgard.ninerealms.com',
  'thornode.ninerealms.com',
  'fulcrum.cash',
  'bchd.fountainhead.cash',
  'cauldron.quest',
  'oracle.cauldron.quest',
  'api.coingecko.com',
  'delphi.cash',
  'relay.damus.io',
  'nos.lol',
  'relay.nostr.band',
  'relay.snort.social',
  'fonts.googleapis.com',
  'fonts.gstatic.com',
];

// ── Install ──────────────────────────────────────
self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE)
      .then(c => c.addAll(APP_SHELL))
      .then(() => self.skipWaiting())
  );
});

// ── Activate — purge old caches ──────────────────
self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys()
      .then(keys => Promise.all(
        keys.filter(k => k !== CACHE).map(k => caches.delete(k))
      ))
      .then(() => self.clients.claim())
  );
});

// ── Fetch ────────────────────────────────────────
self.addEventListener('fetch', e => {
  const url = e.request.url;

  // Skip non-GET, chrome-extension, and WebSocket
  if (e.request.method !== 'GET') return;
  if (url.startsWith('chrome-extension')) return;
  if (url.startsWith('ws://') || url.startsWith('wss://')) return;

  const isNetworkFirst = NETWORK_FIRST.some(h => url.includes(h));

  if (isNetworkFirst) {
    // Network first — live data (prices, pools, relays)
    e.respondWith(
      fetch(e.request)
        .catch(() => caches.match(e.request))
    );
  } else {
    // Cache first — app shell (HTML, icons, manifest)
    e.respondWith(
      caches.match(e.request).then(cached => {
        if (cached) return cached;
        return fetch(e.request).then(res => {
          const clone = res.clone();
          if (res.ok) caches.open(CACHE).then(c => c.put(e.request, clone));
          return res;
        });
      })
    );
  }
});

// ── Push notifications (future) ──────────────────
self.addEventListener('push', e => {
  if (!e.data) return;
  const { title = '0penw0rld', body = '', url = '/' } = e.data.json();
  e.waitUntil(
    self.registration.showNotification(title, {
      body,
      icon: '/icons/icon-192.png',
      badge: '/icons/icon-192.png',
      data: { url },
    })
  );
});

self.addEventListener('notificationclick', e => {
  e.notification.close();
  e.waitUntil(clients.openWindow(e.notification.data?.url || '/'));
});
