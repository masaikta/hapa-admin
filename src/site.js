// Site settings for the public site, edited only by the super administrator on the admin subdomain. Stored in the shared D1 database;
// the public worker reads notice, contacts and flags (GET /api/site). Every change is written to an audit log.
const READY = new WeakSet();
export const PUBLIC_PAGES = ['/contacts/', '/trip/', '/print/', '/scam/', '/analysis/'];
export const SCOPES = ['notice', 'alert', 'contacts', 'articles', 'home', 'feedback'];
const CATS = ['em', 'pol', 'amb', 'fire', 'hosp', 'mh', 'gbv', 'law', 'dis', 'oth', 'stn'];
const clean = (v, n) => String(v == null ? '' : v).replace(/[\u0000-\u001f<>]/g, ' ').trim().slice(0, n);
// A date or a date and time (East Africa Time), e.g. 2026-11-13 or 2026-11-13T14:30.
const date = (v) => { const m = /^(\d{4}-\d{2}-\d{2})(T([01]\d|2[0-3]):[0-5]\d)?$/.exec(String(v || '')); return m && !isNaN(Date.parse(m[1] + 'T00:00:00Z')) ? String(v) : ''; };
const NOW = "strftime('%Y-%m-%dT%H:%M:%SZ','now')";

export async function ensureSite(env) {
  if (READY.has(env.DB)) return;
  await env.DB.batch([
    env.DB.prepare('CREATE TABLE IF NOT EXISTS site_settings (k TEXT PRIMARY KEY, v TEXT NOT NULL, at TEXT, by TEXT)'),
    env.DB.prepare('CREATE TABLE IF NOT EXISTS site_versions (id INTEGER PRIMARY KEY AUTOINCREMENT, k TEXT, v TEXT, at TEXT, who TEXT)'),
    env.DB.prepare('CREATE TABLE IF NOT EXISTS site_audit (id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT, who TEXT, act TEXT, detail TEXT)'),
  ]);
  READY.add(env.DB);
}
export function cleanNums(a) {
  const out = [];
  for (const x of (Array.isArray(a) ? a : []).slice(0, 4)) { const n = clean(x, 24); if (/^(wa:|sms:)?[0-9+() -]{3,20}$/.test(n)) out.push(n); }
  return out;
}
export function cleanContact(c, withId) {
  const name = clean(c && c.name, 80), nums = cleanNums(c && c.nums);
  if (!name || !nums.length) return null;
  const o = { name, nums, en: clean(c.en, 160), sw: clean(c.sw, 160) };
  if (withId) { if (!CATS.includes(c.cat)) return null; o.cat = c.cat; o.county = clean(c.county, 30); o.id = 'x-' + String(c.id || '').replace(/[^a-z0-9-]/gi, '').slice(0, 20); }
  return o;
}
async function read(env, k, d) { const r = await env.DB.prepare('SELECT v FROM site_settings WHERE k=?').bind(k).first(); try { return r ? JSON.parse(r.v) : structuredClone(d); } catch (e) { return structuredClone(d); } }
async function write(env, k, v, who, act, detail) {
  await env.DB.batch([
    env.DB.prepare(`INSERT INTO site_settings (k, v, at, by) VALUES (?,?,${NOW},?) ON CONFLICT(k) DO UPDATE SET v=excluded.v, at=excluded.at, by=excluded.by`).bind(k, JSON.stringify(v), who),
    env.DB.prepare(`INSERT INTO site_versions (k, v, at, who) VALUES (?,?,${NOW},?)`).bind(k, JSON.stringify(v), who),
    env.DB.prepare(`INSERT INTO site_audit (at, who, act, detail) VALUES (${NOW},?,?,?)`).bind(who, act, String(detail).slice(0, 300)),
    env.DB.prepare('DELETE FROM site_versions WHERE k=? AND id NOT IN (SELECT id FROM site_versions WHERE k=? ORDER BY id DESC LIMIT 25)').bind(k, k),
  ]);
}

const DEF = {
  notice: { on: false, en: '', sw: '', level: 'info', from: '', to: '' },
  alert: { on: false, en: '', sw: '', until: '' },
  home: { h_en: '', h_sw: '', new_en: '', new_sw: '', keys: [], featured: [] },
  contacts: { hidden: [], edits: {}, added: [] },
  flags: {}, roles: { editors: [] },
};
const SCOPE_OF = { notice: 'notice', alert: 'alert', home: 'home', contacts: 'contacts' };
const slugOk = (x) => /^[a-z0-9-]{3,90}$/.test(x);
export function cleanHome(b) {
  const keys = [];
  for (const k of (Array.isArray(b && b.keys) ? b.keys : []).slice(0, 6)) {
    const n = cleanNums([k && k.n])[0], l_en = clean(k && k.l_en, 40), l_sw = clean(k && k.l_sw, 40);
    if (n && (l_en || l_sw)) keys.push({ n, l_en: l_en || l_sw, l_sw: l_sw || l_en });
  }
  const featured = [...new Set((Array.isArray(b && b.featured) ? b.featured : []).map((x) => clean(x, 90).toLowerCase()).filter(slugOk))].slice(0, 6);
  return { h_en: clean(b && b.h_en, 120), h_sw: clean(b && b.h_sw, 120), new_en: clean(b && b.new_en, 300), new_sw: clean(b && b.new_sw, 300), keys, featured };
}
const allowed = (who, scope) => !!who && (who.super || (who.scopes || []).includes(scope));
const EMAIL = /^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/;

async function fetchT(url, ms = 6000) {
  const c = new AbortController(), t = setTimeout(() => c.abort(), ms), t0 = Date.now();
  try { const r = await fetch(url, { signal: c.signal, redirect: 'follow' }); return { r, ms: Date.now() - t0 }; } catch (e) { return { r: null, ms: Date.now() - t0 }; } finally { clearTimeout(t); }
}
export const HEALTH_PAGES = ['/', '/sos/', '/contacts/', '/trip/', '/print/', '/scam/', '/analysis/', '/articles', '/api/site', '/api/articles?limit=1', '/data/d.json'];

// who = { email, super, scopes }. Returns [status, body].
export async function siteApi(env, who, act, method, body) {
  await ensureSite(env);
  const actor = who.email;
  const ROOT = env.PUBLIC_ORIGIN || 'https://homesupport.co.ke';
  const need = (scope) => (allowed(who, scope) ? null : [403, { ok: false, error: 'scope' }]);
  if (act === 'site/get' && method === 'GET') {
    const out = {};
    for (const k of Object.keys(DEF)) { if (k === 'roles' && !who.super) continue; out[k] = await read(env, k, DEF[k]); }
    const a = await env.DB.prepare('SELECT at, who, act, detail FROM site_audit ORDER BY id DESC LIMIT 80').all();
    return [200, { ok: true, me: { email: actor, super: !!who.super, scopes: who.super ? SCOPES : who.scopes || [] }, settings: out, audit: a.results || [], pages: PUBLIC_PAGES }];
  }
  if (act === 'site/versions' && method === 'GET') {
    const k = (body && body.k) || '';
    if (!DEF[k] || k === 'roles') return [400, { ok: false, error: 'key' }];
    const bad = k === 'flags' ? (who.super ? null : [403, { ok: false, error: 'scope' }]) : need(SCOPE_OF[k]); if (bad) return bad;
    const rs = await env.DB.prepare('SELECT id, at, who, v FROM site_versions WHERE k=? ORDER BY id DESC LIMIT 12').bind(k).all();
    return [200, { ok: true, rows: (rs.results || []).map((r) => { let v = null; try { v = JSON.parse(r.v); } catch (e) {} return { id: r.id, at: r.at, who: r.who, v }; }) }];
  }
  if (act === 'site/articles' && method === 'GET') {
    const bad = need('articles'); if (bad) return bad;
    try { const rs = await env.DB.prepare('SELECT slug, title_en, county, date, status FROM articles ORDER BY date DESC, id DESC LIMIT 100').all(); return [200, { ok: true, rows: rs.results || [] }]; } catch (e) { return [200, { ok: true, rows: [] }]; }
  }
  if (act === 'site/feedback' && method === 'GET') {
    const bad = need('feedback'); if (bad) return bad;
    try {
      const rs = await env.DB.prepare("SELECT guide, helpful, note, lang, at FROM guide_feedback ORDER BY at DESC LIMIT 100").all();
      const sm = await env.DB.prepare("SELECT guide, SUM(CASE WHEN helpful=1 THEN 1 ELSE 0 END) yes, SUM(CASE WHEN helpful=1 THEN 0 ELSE 1 END) no FROM guide_feedback GROUP BY guide ORDER BY (yes+no) DESC LIMIT 30").all();
      return [200, { ok: true, rows: rs.results || [], summary: sm.results || [] }];
    } catch (e) { return [200, { ok: true, rows: [], summary: [] }]; }
  }
  if (act === 'site/fresh' && method === 'GET') {
    // Dates are read, never guessed: a missing date is shown as missing.
    const out = { ok: true, items: [] };
    const q = async (label, sql) => { try { const r = await env.DB.prepare(sql).first(); out.items.push({ label, at: r ? Object.values(r)[0] : null }); } catch (e) { out.items.push({ label, at: null }); } };
    const { r } = await fetchT(ROOT + '/data/d.json');
    if (r && r.ok) { try { const d = await r.json(); out.items.push({ label: 'Public data built', at: d._built || null }); for (const [k, f] of [['crimes', 'Latest crime incident'], ['attacks', 'Latest attack record'], ['road_crashes', 'Latest road crash'], ['banditry', 'Latest banditry record'], ['reports', 'Latest community report']]) { const ds = (d[k] || []).map((x) => x.date).filter(Boolean).sort(); out.items.push({ label: f, at: ds.length ? ds[ds.length - 1] : null }); } } catch (e) { out.items.push({ label: 'Public data built', at: null }); } }
    else out.items.push({ label: 'Public data built', at: null });
    await q('Latest published article', "SELECT MAX(date) FROM articles WHERE status='published'");
    await q('Last site setting change', 'SELECT MAX(at) FROM site_settings');
    await q('Last feedback received', 'SELECT MAX(at) FROM guide_feedback');
    return [200, out];
  }
  if (act === 'site/health' && method === 'GET') {
    const rows = await Promise.all(HEALTH_PAGES.map(async (p) => { const { r, ms } = await fetchT(ROOT + p); return { path: p, status: r ? r.status : 0, ms }; }));
    return [200, { ok: true, rows, at: new Date().toISOString() }];
  }
  if (act === 'site/live' && method === 'GET') {
    // What visitors get right now from the public site (it caches for about a minute).
    const { r } = await fetchT(ROOT + '/api/site?_=' + Date.now());
    if (!r || !r.ok) return [200, { ok: false, error: 'unreachable' }];
    try { return [200, { ok: true, live: await r.json() }]; } catch (e) { return [200, { ok: false, error: 'unreachable' }]; }
  }
  if (act === 'site/export' && method === 'GET') {
    if (!who.super) return [403, { ok: false, error: 'scope' }];
    const s = {}; for (const k of Object.keys(DEF)) if (k !== 'roles') s[k] = await read(env, k, DEF[k]);
    return [200, { ok: true, backup: { app: 'hapa-admin', v: 1, at: new Date().toISOString(), settings: s } }];
  }
  if (method !== 'POST') return [405, { ok: false, error: 'method' }];
  if (act === 'site/notice') {
    const bad = need('notice'); if (bad) return bad;
    const en = clean(body.en, 240), sw = clean(body.sw, 240), on = !!body.on && !!(en || sw);
    const v = { on, en, sw, level: body.level === 'warn' ? 'warn' : 'info', from: date(body.from), to: date(body.to) };
    await write(env, 'notice', v, actor, 'notice', on ? 'on: ' + (en || sw).slice(0, 80) : 'off');
    return [200, { ok: true, notice: v }];
  }
  if (act === 'site/alert') {
    const bad = need('alert'); if (bad) return bad;
    const en = clean(body.en, 160), sw = clean(body.sw, 160), on = !!body.on && !!(en || sw);
    const until = date(body.until);
    if (on && !until) return [400, { ok: false, error: 'until' }];
    const v = { on, en, sw, until };
    await write(env, 'alert', v, actor, 'alert strip', on ? 'on until ' + until + ': ' + (en || sw).slice(0, 60) : 'off');
    return [200, { ok: true, alert: v }];
  }
  if (act === 'site/home') {
    const bad = need('home'); if (bad) return bad;
    const v = cleanHome(body);
    await write(env, 'home', v, actor, 'home page', 'text ' + (v.h_en || v.h_sw ? 'changed' : 'default') + ', ' + v.keys.length + ' numbers, ' + v.featured.length + ' featured');
    return [200, { ok: true, home: v }];
  }
  if (act === 'site/flags') {
    if (!who.super) return [403, { ok: false, error: 'scope' }];
    const f = {}; for (const p of PUBLIC_PAGES) if (body && body.flags && body.flags[p] === false) f[p] = false;
    await write(env, 'flags', f, actor, 'pages', Object.keys(f).length ? 'off: ' + Object.keys(f).join(' ') : 'all on');
    return [200, { ok: true, flags: f }];
  }
  if (act === 'site/contacts') {
    const bad = need('contacts'); if (bad) return bad;
    const C = await read(env, 'contacts', DEF.contacts); C.hidden = C.hidden || []; C.edits = C.edits || {}; C.added = C.added || [];
    const idc = (x) => String(x || '').replace(/[^a-z0-9-]/gi, '').slice(0, 70);
    const id = idc(body && body.id), op = body && body.op;
    if (op === 'hide' && id) { if (!C.hidden.includes(id) && C.hidden.length < 300) C.hidden.push(id); }
    else if (op === 'show' && id) C.hidden = C.hidden.filter((x) => x !== id);
    else if ((op === 'hide_many' || op === 'show_many') && Array.isArray(body.ids)) {
      const ids = body.ids.map(idc).filter(Boolean).slice(0, 300);
      if (op === 'hide_many') { for (const x of ids) if (!C.hidden.includes(x)) C.hidden.push(x); if (C.hidden.length > 300) return [400, { ok: false, error: 'limit' }]; } else C.hidden = C.hidden.filter((x) => !ids.includes(x));
    }
    else if (op === 'edit' && id) { const c = cleanContact(body.contact, false); if (!c) return [400, { ok: false, error: 'contact' }]; if (Object.keys(C.edits).length >= 200 && !C.edits[id]) return [400, { ok: false, error: 'limit' }]; C.edits[id] = c; }
    else if (op === 'reset' && id) delete C.edits[id];
    else if (op === 'add') { if (C.added.length >= 100) return [400, { ok: false, error: 'limit' }]; const c = cleanContact({ ...(body.contact || {}), id: Date.now().toString(36) }, true); if (!c) return [400, { ok: false, error: 'contact' }]; C.added.push(c); }
    else if (op === 'remove' && id) C.added = C.added.filter((x) => x.id !== id);
    else return [400, { ok: false, error: 'op' }];
    await write(env, 'contacts', C, actor, 'contacts ' + op, id || (body.ids ? body.ids.length + ' entries' : '') || (body.contact && body.contact.name) || '');
    return [200, { ok: true, contacts: C }];
  }
  if (act === 'site/article') {
    const bad = need('articles'); if (bad) return bad;
    const slug = clean(body && body.slug, 120).toLowerCase(), st = body && body.status;
    if (!slug || !['published', 'draft'].includes(st)) return [400, { ok: false, error: 'bad' }];
    const r = await env.DB.prepare('UPDATE articles SET status=? WHERE slug=?').bind(st, slug).run();
    if (!(r.meta && r.meta.changes)) return [404, { ok: false, error: 'notfound' }];
    await env.DB.prepare(`INSERT INTO site_audit (at, who, act, detail) VALUES (${NOW},?,?,?)`).bind(actor, 'article ' + st, slug).run();
    return [200, { ok: true }];
  }
  if (act === 'site/preview') {
    const bad = need('articles'); if (bad) return bad;
    const slug = clean(body && body.slug, 120).toLowerCase();
    if (!slugOk(slug) || !(await env.DB.prepare('SELECT 1 x FROM articles WHERE slug=?').bind(slug).first())) return [404, { ok: false, error: 'notfound' }];
    const m = await read(env, 'previews', {}), now = Date.now();
    for (const k of Object.keys(m)) if (!(m[k].exp > now)) delete m[k];
    for (const k of Object.keys(m).slice(0, Math.max(0, Object.keys(m).length - 19))) delete m[k];
    const t = [...crypto.getRandomValues(new Uint8Array(16))].map((b) => b.toString(16).padStart(2, '0')).join('');
    m[t] = { slug, exp: now + 2 * 3600e3 };
    await env.DB.prepare(`INSERT INTO site_settings (k, v, at, by) VALUES ('previews',?,${NOW},?) ON CONFLICT(k) DO UPDATE SET v=excluded.v, at=excluded.at, by=excluded.by`).bind(JSON.stringify(m), actor).run();
    await env.DB.prepare(`INSERT INTO site_audit (at, who, act, detail) VALUES (${NOW},?,?,?)`).bind(actor, 'preview link', slug).run();
    return [200, { ok: true, url: ROOT + '/a/' + slug + '?preview=' + t, minutes: 120 }];
  }
  if (act === 'site/restore') {
    const row = await env.DB.prepare('SELECT k, v FROM site_versions WHERE id=?').bind(Number(body && body.id) || 0).first();
    if (!row || !DEF[row.k] || row.k === 'roles') return [404, { ok: false, error: 'notfound' }];
    if (row.k === 'flags' ? !who.super : !allowed(who, SCOPE_OF[row.k])) return [403, { ok: false, error: 'scope' }];
    let v; try { v = JSON.parse(row.v); } catch (e) { return [400, { ok: false, error: 'bad' }]; }
    await write(env, row.k, v, actor, 'restore ' + row.k, 'version ' + Number(body.id));
    return [200, { ok: true, k: row.k, value: v }];
  }
  if (act === 'site/roles') {
    if (!who.super) return [403, { ok: false, error: 'scope' }];
    const seen = new Set(), editors = [];
    for (const e of (Array.isArray(body && body.editors) ? body.editors : []).slice(0, 10)) {
      const email = clean(e && e.email, 120).toLowerCase(), scopes = (Array.isArray(e && e.scopes) ? e.scopes : []).filter((x) => SCOPES.includes(x));
      if (!EMAIL.test(email) || seen.has(email) || !scopes.length) continue; seen.add(email); editors.push({ email, scopes });
    }
    await write(env, 'roles', { editors }, actor, 'roles', editors.map((e) => e.email + ' [' + e.scopes.join(',') + ']').join('; ') || 'none');
    return [200, { ok: true, roles: { editors } }];
  }
  if (act === 'site/import') {
    if (!who.super) return [403, { ok: false, error: 'scope' }];
    const s = body && body.backup && body.backup.settings; if (!s || body.backup.app !== 'hapa-admin') return [400, { ok: false, error: 'bad' }];
    const done = [];
    if (s.notice) { const b = s.notice, en = clean(b.en, 240), sw = clean(b.sw, 240); await write(env, 'notice', { on: !!b.on && !!(en || sw), en, sw, level: b.level === 'warn' ? 'warn' : 'info', from: date(b.from), to: date(b.to) }, actor, 'import', 'notice'); done.push('notice'); }
    if (s.alert) { const b = s.alert, en = clean(b.en, 160), sw = clean(b.sw, 160), until = date(b.until); await write(env, 'alert', { on: !!b.on && !!(en || sw) && !!until, en, sw, until }, actor, 'import', 'alert'); done.push('alert'); }
    if (s.home) { await write(env, 'home', cleanHome(s.home), actor, 'import', 'home'); done.push('home'); }
    if (s.flags) { const f = {}; for (const p of PUBLIC_PAGES) if (s.flags[p] === false) f[p] = false; await write(env, 'flags', f, actor, 'import', 'pages'); done.push('pages'); }
    if (s.contacts) {
      const c = s.contacts, C = { hidden: [], edits: {}, added: [] };
      C.hidden = (Array.isArray(c.hidden) ? c.hidden : []).map((x) => String(x).replace(/[^a-z0-9-]/gi, '').slice(0, 70)).filter(Boolean).slice(0, 300);
      for (const [id, v] of Object.entries(c.edits || {}).slice(0, 200)) { const cc = cleanContact(v, false); if (cc) C.edits[String(id).replace(/[^a-z0-9-]/gi, '').slice(0, 70)] = cc; }
      for (const v of (Array.isArray(c.added) ? c.added : []).slice(0, 100)) { const cc = cleanContact(v, true); if (cc) C.added.push(cc); }
      await write(env, 'contacts', C, actor, 'import', 'contacts'); done.push('contacts');
    }
    return [200, { ok: true, done }];
  }
  return [404, { ok: false, error: 'notfound' }];
}
