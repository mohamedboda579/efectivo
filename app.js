(() => {
'use strict';
const $ = (s) => document.querySelector(s);
const te = new TextEncoder(), td = new TextDecoder();
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const b64 = (u8) => { let s = ''; u8.forEach((x) => { s += String.fromCharCode(x); }); return btoa(s); };
const norm = (s) => String(s).toLowerCase().replace(/[\s-]/g, '');
const ls = {
  get: (k) => { try { return localStorage.getItem(k); } catch (e) { return null; } },
  set: (k, v) => { try { localStorage.setItem(k, v); } catch (e) { /* sin almacenamiento */ } },
  del: (k) => { try { localStorage.removeItem(k); } catch (e) { /* nada */ } },
};

let vault = null, payload = null, cfg = null;

/* ---------- cifrado ---------- */
const deriveRaw = async (pass, salt, iter) => {
  const base = await crypto.subtle.importKey('raw', te.encode(norm(pass)), 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({name: 'PBKDF2', salt, iterations: iter, hash: 'SHA-256'}, base, 256));
};
const openPayload = async (raw) => {
  const kek = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']);
  const pk = await crypto.subtle.decrypt({name: 'AES-GCM', iv: unb64(vault.iv)}, kek, unb64(vault.ct));
  const priv = await crypto.subtle.importKey('pkcs8', pk, {name: 'RSA-OAEP', hash: 'SHA-256'}, false, ['decrypt']);
  const kraw = await crypto.subtle.decrypt({name: 'RSA-OAEP'}, priv, unb64(payload.k));
  const key = await crypto.subtle.importKey('raw', kraw, 'AES-GCM', false, ['decrypt']);
  const pt = await crypto.subtle.decrypt({name: 'AES-GCM', iv: unb64(payload.iv)}, key, unb64(payload.ct));
  return JSON.parse(td.decode(pt));
};

/* ---------- motor del cuadro (misma interfaz que usa la página) ---------- */
const makeDash = () => {
  const loaders = {}, calcs = {}, draws = {}, listeners = [];
  let raw = {}, memo = {}, ready = false;
  const rowsOf = (id) => { const d = api.data(id); return Array.isArray(d.data) ? d.data : (d.data == null ? [] : d.data); };
  const api = {
    colors: ['#2f6fdb', '#e07a3c', '#2a9d8f', '#8e5bd0', '#c0392b', '#7a7f87'],
    loader: (id, o) => { loaders[id] = o.fn; },
    calc: (id, o) => { calcs[id] = o; },
    data: (id) => {
      if (!ready) return {status: 'loading', data: calcs[id] ? null : [], columns: []};
      if (memo[id]) return memo[id];
      let out;
      try {
        if (calcs[id]) {
          const c = calcs[id];
          const res = c.fn(...c.inputs.map((i) => (calcs[i] ? api.data(i).data : rowsOf(i))));
          out = {status: 'ok', data: res, columns: res && res[0] ? Object.keys(res[0]) : []};
        } else if (raw[id]) {
          if (raw[id].error) out = {status: 'error', data: [], columns: [], message: String(raw[id].error)};
          else {
            const r = loaders[id] ? loaders[id]({answer: raw[id].answer}) : {rows: (raw[id].answer.values || [])};
            out = {status: 'ok', data: r.rows, columns: r.columns || []};
          }
        } else out = {status: 'missing', data: [], columns: []};
      } catch (e) {
        out = {status: 'error', data: calcs[id] ? null : [], columns: [], message: e.message};
        console.error('[' + id + ']', e);
      }
      memo[id] = out;
      return out;
    },
    onData: (fn) => { listeners.push(fn); },
    draw: (name, fn) => {
      if (fn) draws[name] = fn;
      if (!ready || !draws[name]) return;
      document.querySelectorAll('[data-draw="' + name + '"]').forEach((el) => {
        try { draws[name](el); } catch (e) { console.error('[draw ' + name + ']', e); }
      });
    },
    refresh: () => {}, params: () => ({}), setParams: () => {}, resetParams: () => {}, setLink: () => {},
  };
  api.__set = (data) => {
    raw = data; memo = {}; ready = true;
    listeners.forEach((fn) => { try { fn(); } catch (e) { console.error(e); } });
    Object.keys(draws).forEach((n) => api.draw(n));
  };
  api.__redraw = () => { if (ready) { listeners.forEach((fn) => { try { fn(); } catch (e) { console.error(e); } }); Object.keys(draws).forEach((n) => api.draw(n)); } };
  return api;
};

/* ---------- datos en vivo ---------- */
let lastLoad = 0, loading = false, lastAt = null;
const stamp = (iso) => new Date(iso).toLocaleTimeString('es-PA', {hour: 'numeric', minute: '2-digit'});
const setStatus = (t, bad) => { const el = $('#bar-estado'); el.textContent = t; el.classList.toggle('bad', !!bad); };
const apply = (j) => { window.dash.__set(j.data); lastAt = j.at; };

const load = async () => {
  if (loading || !cfg) return;
  loading = true; $('#bar-refresh').classList.add('spin'); setStatus('Actualizando…');
  try {
    const u = cfg.url + (cfg.url.includes('?') ? '&' : '?') + 't=' + encodeURIComponent(cfg.token) + '&_=' + Date.now();
    const r = await fetch(u);
    const j = await r.json();
    if (j.error) throw new Error(j.error);
    ls.set('ef_data', JSON.stringify(j));
    apply(j); lastLoad = Date.now();
    setStatus('Actualizado ' + stamp(j.at));
  } catch (e) {
    console.error(e);
    setStatus(lastAt ? 'Sin conexión · datos de las ' + stamp(lastAt) : 'No se pudo cargar. Toca ↻', true);
  } finally {
    loading = false; $('#bar-refresh').classList.remove('spin');
  }
};

/* ---------- arranque ---------- */
const boot = (bundle) => {
  cfg = bundle.cfg;
  $('#lock').hidden = true; $('#app').hidden = false;
  const st = document.createElement('style'); st.textContent = bundle.style; document.head.append(st);
  $('#dash-root').innerHTML = bundle.html;
  window.dash = makeDash();
  window.addEventListener('error', (e) => setStatus('Error: ' + e.message, true));
  const s = document.createElement('script'); s.textContent = bundle.script; document.body.append(s);
  const cached = ls.get('ef_data');
  if (cached) { try { const j = JSON.parse(cached); apply(j); setStatus('Datos de las ' + stamp(j.at) + ' · actualizando…'); } catch (e) { ls.del('ef_data'); } }
  load();
  $('#bar-refresh').addEventListener('click', load);
  document.addEventListener('visibilitychange', () => { if (!document.hidden && Date.now() - lastLoad > 90000) load(); });
  let t; window.addEventListener('resize', () => { clearTimeout(t); t = setTimeout(() => window.dash.__redraw(), 150); });
};

const showLock = () => {
  $('#lock').hidden = false; $('#app').hidden = true;
  const f = $('#lock-form'), inp = $('#lock-pass'), err = $('#lock-err'), btn = $('#lock-btn');
  f.addEventListener('submit', async (ev) => {
    ev.preventDefault(); err.textContent = ''; btn.disabled = true; btn.textContent = 'Abriendo…';
    try {
      const raw = await deriveRaw(inp.value, unb64(vault.salt), vault.iter);
      const bundle = await openPayload(raw);
      if ($('#lock-remember').checked) ls.set('ef_k', b64(raw));
      inp.value = '';
      boot(bundle);
    } catch (e) {
      err.textContent = 'Clave incorrecta';
      btn.disabled = false; btn.textContent = 'Entrar';
    }
  });
  inp.focus();
};

const start = async () => {
  if ('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js').catch(() => {});
  try {
    [vault, payload] = await Promise.all(['vault.json', 'payload.json'].map((f) => fetch(f, {cache: 'no-store'}).then((r) => { if (!r.ok) throw new Error(f); return r.json(); })));
  } catch (e) { $('#lock').hidden = false; $('#lock-err').textContent = 'Sin conexión. Intenta de nuevo.'; return; }
  const saved = ls.get('ef_k');
  if (saved) {
    try { boot(await openPayload(unb64(saved))); return; } catch (e) { ls.del('ef_k'); }
  }
  showLock();
};
start();
})();
