// 0penw0rld Shell — lang switcher, app switcher, disconnect, endpoint settings
(function () {
'use strict';

const APPS = [
  { name: '00 Wallet', url: 'wallet.html' },
  { name: '00 Chat',   url: 'chat.html'   },
  { name: '00 Pay',    url: 'pay.html'    },
  { name: '00 DEX',    url: 'dex.html'    },
  { name: '00 Loan',   url: 'loan.html'   },
  { name: '00 ID',     url: 'id.html'     },
  { name: '00 Mesh',   url: 'mesh.html'   },
  { name: '00 Fusion', url: 'fusion.html' },
];

const LANGS = ['EN', 'FR', 'ES', 'CN'];

const T = {
  EN: { disc: 'DISCONNECT', apps: 'APPS', confirm: 'Clear all data and disconnect?', connect: 'CONNECT' },
  FR: { disc: 'DÉCONNECTER', apps: 'APPS', confirm: 'Effacer les données et déconnecter ?', connect: 'CONNECTER' },
  ES: { disc: 'DESCONECTAR', apps: 'APPS', confirm: '¿Borrar datos y desconectar?', connect: 'CONECTAR' },
  CN: { disc: '断开连接',    apps: '应用', confirm: '清除数据并断开连接？', connect: '连接' },
};

function isConnected() {
  return !!(localStorage.getItem('00_wif') || localStorage.getItem('00_pub') || localStorage.getItem('00_ledger') || localStorage.getItem('00wallet_vault') || localStorage.getItem('00_wc_session'));
}

// ── Endpoint defaults & config ────────────────────────────────
const EP_DEFAULTS = {
  fulcrum: ['wss://bch.imaginary.cash:50004','wss://electroncash.de:50004','wss://bch.loping.net:50004'],
  relays:  ['wss://relay.damus.io','wss://nos.lol','wss://relay.nostr.band','wss://relay.snort.social'],
  indexer: 'https://indexer.riften.net',
  midgard: 'https://midgard.ninerealms.com/v2',
  meta:    'https://meta.riften.net',
};

function _epRead(key, fallback) {
  try {
    const v = localStorage.getItem('00_ep_' + key);
    if (!v) return fallback;
    const parsed = JSON.parse(v);
    if (Array.isArray(fallback)) return Array.isArray(parsed) && parsed.length ? parsed : fallback;
    return typeof parsed === 'string' && parsed ? parsed : fallback;
  } catch (e) { return fallback; }
}

window._00ep = {
  get fulcrum() { return _epRead('fulcrum', EP_DEFAULTS.fulcrum); },
  get relays()  { return _epRead('relays',  EP_DEFAULTS.relays); },
  get indexer() { return _epRead('indexer', EP_DEFAULTS.indexer); },
  get midgard() { return _epRead('midgard', EP_DEFAULTS.midgard); },
  get meta()    { return _epRead('meta',    EP_DEFAULTS.meta); },
  defaults: EP_DEFAULTS,
};

let _lang = localStorage.getItem('00_lang') || 'EN';
function t(k) { return (T[_lang] || T.EN)[k] || k; }

function setLang(lang) {
  _lang = lang;
  localStorage.setItem('00_lang', lang);
  document.querySelectorAll('[data-i18n]').forEach(el => { el.textContent = t(el.dataset.i18n); });
  document.querySelectorAll('.shell-lang-cur').forEach(el => { el.textContent = lang; });
  document.querySelectorAll('.shell-lang-opt').forEach(opt => {
    opt.classList.toggle('active', opt.dataset.lang === lang);
  });
  if (typeof window._onLangChange === 'function') window._onLangChange(lang);
}

async function disconnect() {
  if (!confirm(t('confirm'))) return;
  localStorage.clear();
  sessionStorage.clear();
  if ('serviceWorker' in navigator) {
    const regs = await navigator.serviceWorker.getRegistrations();
    await Promise.all(regs.map(r => r.unregister()));
  }
  if ('caches' in window) {
    const keys = await caches.keys();
    await Promise.all(keys.map(k => caches.delete(k)));
  }
  try { if (window._ledgerDevice) await window._ledgerDevice.close(); } catch (e) {}
  try { if (window.wcDisconnect) await window.wcDisconnect(); } catch (e) {}
  window.location.replace('/');
}

window._shellSetLang    = setLang;
window._shellDisconnect = disconnect;

// ── CSS ────────────────────────────────────────────────────────
const st = document.createElement('style');
st.textContent = `
  .shell-controls {
    display: flex; align-items: center; gap: 6px;
    font-family: 'Share Tech Mono', monospace;
  }
  .shell-drop { position: relative; }
  .shell-btn {
    background: transparent; border: 1px solid rgba(0,255,65,.18);
    color: rgba(0,255,65,.45); padding: 3px 8px;
    font-family: 'Share Tech Mono', monospace; font-size: 10px;
    letter-spacing: 1px; cursor: pointer; transition: .15s; white-space: nowrap;
    line-height: 1.4;
  }
  .shell-btn:hover { border-color: rgba(0,255,65,.5); color: #00ff41; }
  .shell-menu {
    display: none; position: absolute; top: calc(100% + 5px); right: 0;
    background: rgba(2,10,3,.97); border: 1px solid rgba(0,255,65,.2);
    box-shadow: 0 8px 28px rgba(0,0,0,.85); z-index: 9999; min-width: 148px;
  }
  .shell-menu.open { display: block; }
  .shell-menu a, .shell-menu-item {
    display: block; padding: 8px 14px; font-size: 11px; letter-spacing: 1px;
    color: rgba(0,255,65,.5); text-decoration: none; cursor: pointer;
    border-bottom: 1px solid rgba(0,255,65,.05); transition: .1s;
    font-family: 'Share Tech Mono', monospace;
  }
  .shell-menu a:last-child, .shell-menu-item:last-child { border-bottom: none; }
  .shell-menu a:hover, .shell-menu-item:hover { background: rgba(0,255,65,.05); color: #00ff41; }
  .shell-menu a.cur { color: #00ff41; border-left: 2px solid #00ff41; padding-left: 12px; }
  .shell-menu-item.active { color: #00ff41; }
  .shell-disc {
    background: transparent; border: 1px solid rgba(255,50,50,.22);
    color: rgba(255,80,80,.4); padding: 3px 8px;
    font-family: 'Share Tech Mono', monospace; font-size: 10px;
    letter-spacing: 1px; cursor: pointer; transition: .15s; white-space: nowrap;
    line-height: 1.4;
  }
  .shell-disc:hover {
    border-color: rgba(255,60,60,.6); color: rgba(255,110,110,.95);
    box-shadow: 0 0 8px rgba(255,40,40,.12);
  }
  /* ── Settings modal ── */
  .ep-overlay {
    display:none; position:fixed; inset:0; z-index:10000;
    background:rgba(0,0,0,.85); backdrop-filter:blur(6px);
    align-items:center; justify-content:center;
    font-family:'Share Tech Mono',monospace;
  }
  .ep-overlay.open { display:flex; }
  .ep-modal {
    background:#060e06; border:1px solid rgba(0,255,65,.2);
    box-shadow:0 0 40px rgba(0,255,65,.08); padding:24px 28px;
    max-width:480px; width:92vw; max-height:85vh; overflow-y:auto;
  }
  .ep-title {
    font-size:13px; letter-spacing:2px; color:#00ff41;
    margin-bottom:18px; text-transform:uppercase;
  }
  .ep-group { margin-bottom:14px; }
  .ep-label {
    font-size:9px; letter-spacing:1.5px; color:rgba(0,255,65,.4);
    margin-bottom:4px; text-transform:uppercase;
  }
  .ep-input, .ep-textarea {
    width:100%; background:rgba(0,255,65,.03);
    border:1px solid rgba(0,255,65,.12); color:#00ff41;
    font-family:'Share Tech Mono',monospace; font-size:11px;
    padding:6px 8px; outline:none; transition:.15s;
  }
  .ep-input:focus, .ep-textarea:focus { border-color:rgba(0,255,65,.4); }
  .ep-textarea { resize:vertical; min-height:60px; line-height:1.5; }
  .ep-hint {
    font-size:8px; color:rgba(0,255,65,.25); margin-top:2px;
    letter-spacing:.5px;
  }
  .ep-actions {
    display:flex; gap:8px; margin-top:18px; justify-content:flex-end;
  }
  .ep-save {
    background:rgba(0,255,65,.1); border:1px solid rgba(0,255,65,.3);
    color:#00ff41; padding:6px 16px; font-family:'Share Tech Mono',monospace;
    font-size:10px; letter-spacing:1px; cursor:pointer; transition:.15s;
  }
  .ep-save:hover { background:rgba(0,255,65,.2); }
  .ep-reset {
    background:transparent; border:1px solid rgba(255,80,80,.2);
    color:rgba(255,80,80,.5); padding:6px 16px; font-family:'Share Tech Mono',monospace;
    font-size:10px; letter-spacing:1px; cursor:pointer; transition:.15s;
  }
  .ep-reset:hover { border-color:rgba(255,80,80,.5); color:rgba(255,110,110,.9); }
  .ep-close {
    background:transparent; border:1px solid rgba(0,255,65,.15);
    color:rgba(0,255,65,.35); padding:6px 16px; font-family:'Share Tech Mono',monospace;
    font-size:10px; letter-spacing:1px; cursor:pointer; transition:.15s;
  }
  .ep-close:hover { border-color:rgba(0,255,65,.4); color:#00ff41; }
  .ep-note {
    font-size:8px; color:rgba(0,255,65,.2); margin-top:12px;
    letter-spacing:.5px; text-align:center;
  }
`;
document.head.appendChild(st);

// ── Settings modal ────────────────────────────────────────────
function buildSettingsModal() {
  const overlay = document.createElement('div');
  overlay.className = 'ep-overlay';
  overlay.onclick = e => { if (e.target === overlay) overlay.classList.remove('open'); };

  const fulcrumVal = () => (JSON.parse(localStorage.getItem('00_ep_fulcrum') || 'null') || EP_DEFAULTS.fulcrum).join('\n');
  const relaysVal  = () => (JSON.parse(localStorage.getItem('00_ep_relays')  || 'null') || EP_DEFAULTS.relays).join('\n');
  const indexerVal = () => localStorage.getItem('00_ep_indexer') ? JSON.parse(localStorage.getItem('00_ep_indexer')) : EP_DEFAULTS.indexer;
  const midgardVal = () => localStorage.getItem('00_ep_midgard') ? JSON.parse(localStorage.getItem('00_ep_midgard')) : EP_DEFAULTS.midgard;
  const metaVal    = () => localStorage.getItem('00_ep_meta')    ? JSON.parse(localStorage.getItem('00_ep_meta'))    : EP_DEFAULTS.meta;

  overlay.innerHTML = `
    <div class="ep-modal">
      <div class="ep-title">// ENDPOINTS</div>

      <div class="ep-group">
        <div class="ep-label">FULCRUM / ELECTRUM NODES</div>
        <textarea class="ep-textarea" id="ep-fulcrum" rows="3">${fulcrumVal()}</textarea>
        <div class="ep-hint">one wss:// URL per line</div>
      </div>

      <div class="ep-group">
        <div class="ep-label">NOSTR RELAYS</div>
        <textarea class="ep-textarea" id="ep-relays" rows="4">${relaysVal()}</textarea>
        <div class="ep-hint">one wss:// URL per line</div>
      </div>

      <div class="ep-group">
        <div class="ep-label">CAULDRON INDEXER</div>
        <input class="ep-input" id="ep-indexer" value="${indexerVal()}">
      </div>

      <div class="ep-group">
        <div class="ep-label">THORCHAIN MIDGARD</div>
        <input class="ep-input" id="ep-midgard" value="${midgardVal()}">
      </div>

      <div class="ep-group">
        <div class="ep-label">META / ICON SERVICE</div>
        <input class="ep-input" id="ep-meta" value="${metaVal()}">
      </div>

      <div class="ep-actions">
        <button class="ep-reset" id="ep-btn-reset">RESET</button>
        <button class="ep-close" id="ep-btn-close">CANCEL</button>
        <button class="ep-save" id="ep-btn-save">SAVE</button>
      </div>
      <div class="ep-note">changes apply on page reload</div>
    </div>`;

  overlay.querySelector('#ep-btn-close').onclick = () => overlay.classList.remove('open');

  overlay.querySelector('#ep-btn-save').onclick = () => {
    const lines = s => s.split('\n').map(l => l.trim()).filter(l => l.startsWith('wss://'));
    const fulcrum = lines(overlay.querySelector('#ep-fulcrum').value);
    const relays  = lines(overlay.querySelector('#ep-relays').value);
    const indexer = overlay.querySelector('#ep-indexer').value.trim();
    const midgard = overlay.querySelector('#ep-midgard').value.trim();
    const meta    = overlay.querySelector('#ep-meta').value.trim();
    if (fulcrum.length) localStorage.setItem('00_ep_fulcrum', JSON.stringify(fulcrum));
    else localStorage.removeItem('00_ep_fulcrum');
    if (relays.length)  localStorage.setItem('00_ep_relays', JSON.stringify(relays));
    else localStorage.removeItem('00_ep_relays');
    if (indexer) localStorage.setItem('00_ep_indexer', JSON.stringify(indexer));
    else localStorage.removeItem('00_ep_indexer');
    if (midgard) localStorage.setItem('00_ep_midgard', JSON.stringify(midgard));
    else localStorage.removeItem('00_ep_midgard');
    if (meta) localStorage.setItem('00_ep_meta', JSON.stringify(meta));
    else localStorage.removeItem('00_ep_meta');
    overlay.classList.remove('open');
  };

  overlay.querySelector('#ep-btn-reset').onclick = () => {
    ['fulcrum','relays','indexer','midgard','meta'].forEach(k => localStorage.removeItem('00_ep_' + k));
    overlay.querySelector('#ep-fulcrum').value = EP_DEFAULTS.fulcrum.join('\n');
    overlay.querySelector('#ep-relays').value  = EP_DEFAULTS.relays.join('\n');
    overlay.querySelector('#ep-indexer').value  = EP_DEFAULTS.indexer;
    overlay.querySelector('#ep-midgard').value  = EP_DEFAULTS.midgard;
    overlay.querySelector('#ep-meta').value     = EP_DEFAULTS.meta;
  };

  document.body.appendChild(overlay);
  return overlay;
}

let _settingsOverlay = null;
function openSettings() {
  if (!_settingsOverlay) _settingsOverlay = buildSettingsModal();
  // Refresh values on open
  const ov = _settingsOverlay;
  ov.querySelector('#ep-fulcrum').value = (JSON.parse(localStorage.getItem('00_ep_fulcrum') || 'null') || EP_DEFAULTS.fulcrum).join('\n');
  ov.querySelector('#ep-relays').value  = (JSON.parse(localStorage.getItem('00_ep_relays')  || 'null') || EP_DEFAULTS.relays).join('\n');
  ov.querySelector('#ep-indexer').value = localStorage.getItem('00_ep_indexer') ? JSON.parse(localStorage.getItem('00_ep_indexer')) : EP_DEFAULTS.indexer;
  ov.querySelector('#ep-midgard').value = localStorage.getItem('00_ep_midgard') ? JSON.parse(localStorage.getItem('00_ep_midgard')) : EP_DEFAULTS.midgard;
  ov.querySelector('#ep-meta').value    = localStorage.getItem('00_ep_meta')    ? JSON.parse(localStorage.getItem('00_ep_meta'))    : EP_DEFAULTS.meta;
  ov.classList.add('open');
}

// ── Build controls ─────────────────────────────────────────────
function buildControls(showApps) {
  const cur  = window.location.pathname.split('/').pop() || 'index.html';
  const wrap = document.createElement('div');
  wrap.className = 'shell-controls';

  if (showApps) {
    const appsHtml = APPS.map(a =>
      `<a href="${a.url}"${a.url === cur ? ' class="cur"' : ''}>${a.name}</a>`
    ).join('');
    const d = document.createElement('div');
    d.className = 'shell-drop';
    d.innerHTML = `
      <button class="shell-btn" data-i18n="apps">${t('apps')} ▾</button>
      <div class="shell-menu">${appsHtml}</div>`;
    d.querySelector('.shell-btn').onclick = e => {
      e.stopPropagation();
      d.querySelector('.shell-menu').classList.toggle('open');
    };
    wrap.appendChild(d);
  }

  // Lang switcher
  const langD = document.createElement('div');
  langD.className = 'shell-drop';
  langD.innerHTML = `
    <button class="shell-btn"><span class="shell-lang-cur">${_lang}</span> ▾</button>
    <div class="shell-menu">
      ${LANGS.map(l =>
        `<div class="shell-menu-item shell-lang-opt${l === _lang ? ' active' : ''}" data-lang="${l}">${l}</div>`
      ).join('')}
    </div>`;
  langD.querySelector('.shell-btn').onclick = e => {
    e.stopPropagation();
    langD.querySelector('.shell-menu').classList.toggle('open');
  };
  langD.querySelectorAll('.shell-lang-opt').forEach(opt => {
    opt.onclick = e => {
      e.stopPropagation();
      setLang(opt.dataset.lang);
      langD.querySelector('.shell-menu').classList.remove('open');
    };
  });
  wrap.appendChild(langD);

  // Settings button
  const gear = document.createElement('button');
  gear.className = 'shell-btn';
  gear.textContent = '\u2699';
  gear.title = 'Endpoints';
  gear.onclick = e => { e.stopPropagation(); openSettings(); };
  wrap.appendChild(gear);

  // Connect / Disconnect
  const disc = document.createElement('button');
  if (isConnected()) {
    disc.className = 'shell-disc';
    disc.dataset.i18n = 'disc';
    disc.textContent = t('disc');
    disc.onclick = disconnect;
  } else {
    disc.className = 'shell-btn';
    disc.dataset.i18n = 'connect';
    disc.textContent = t('connect');
    disc.onclick = () => { window.location.href = 'wallet.html'; };
  }
  wrap.appendChild(disc);

  return wrap;
}

// Close all menus on outside click
document.addEventListener('click', () => {
  document.querySelectorAll('.shell-menu').forEach(m => m.classList.remove('open'));
});

// ── Inject ─────────────────────────────────────────────────────
function inject() {
  const path      = window.location.pathname.split('/').pop() || 'index.html';
  const isLanding = path === '' || path === 'index.html';
  const isDocs    = path === 'docs.html';

  // Remove blinking cursor to avoid visual conflict with shell controls
  document.querySelectorAll('.blink').forEach(el => el.remove());

  if (isLanding) {
    // Append into terminal-bar right span (after clock)
    const bar   = document.querySelector('.terminal-bar');
    if (!bar) return;
    const right = bar.querySelector('span:last-child');
    if (right) {
      right.style.gap = '16px';
      right.appendChild(buildControls(false));
    }
  } else if (isDocs) {
    const bar = document.querySelector('.top-bar');
    if (!bar) return;
    bar.appendChild(buildControls(true));
  } else {
    // App pages: fixed overlay — no DOM manipulation of existing layout
    const ctrl = buildControls(true);
    ctrl.style.cssText = `
      position:fixed; top:0; right:0; z-index:9000;
      background:rgba(2,10,3,.88); backdrop-filter:blur(4px);
      padding:6px 10px;
      border-bottom:1px solid rgba(0,255,65,.1);
      border-left:1px solid rgba(0,255,65,.1);
    `;
    document.body.appendChild(ctrl);
  }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', inject);
} else {
  inject();
}

})();
