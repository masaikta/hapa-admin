// Site settings for the public site, edited only by the super administrator on the admin subdomain. Stored in the shared D1 database;
// the public worker reads notice, contacts and flags (GET /api/site). Every change is written to an audit log.
const READY = new WeakSet();
export const PUBLIC_PAGES = ['/contacts/', '/trip/', '/print/', '/scam/', '/analysis/'];
const CATS = ['em', 'pol', 'amb', 'fire', 'hosp', 'mh', 'gbv', 'law', 'dis', 'oth', 'stn'];
const clean = (v, n) => String(v == null ? '' : v).replace(/[\u0000-\u001f<>]/g, ' ').trim().slice(0, n);
const date = (v) => (/^\d{4}-\d{2}-\d{2}$/.test(String(v || '')) && !isNaN(Date.parse(v + 'T00:00:00Z')) ? String(v) : '');
const NOW = "strftime('%Y-%m-%dT%H:%M:%SZ','now')";

export async function ensureSite(env) {
  if (READY.has(env.DB)) return;
  await env.DB.batch([
    env.DB.prepare('CREATE TABLE IF NOT EXISTS site_settings (k TEXT PRIMARY KEY, v TEXT NOT NULL, at TEXT, by TEXT)'),
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
async function read(env, k, d) { const r = await env.DB.prepare('SELECT v FROM site_settings WHERE k=?').bind(k).first(); try { return r ? JSON.parse(r.v) : d; } catch (e) { return d; } }
async function write(env, k, v, who, act, detail) {
  await env.DB.batch([
    env.DB.prepare(`INSERT INTO site_settings (k, v, at, by) VALUES (?,?,${NOW},?) ON CONFLICT(k) DO UPDATE SET v=excluded.v, at=excluded.at, by=excluded.by`).bind(k, JSON.stringify(v), who),
    env.DB.prepare(`INSERT INTO site_audit (at, who, act, detail) VALUES (${NOW},?,?,?)`).bind(who, act, String(detail).slice(0, 300)),
  ]);
}

// Returns [status, body]. Super administrator only: the caller checks who.super.
export async function siteApi(env, actor, act, method, body) {
  await ensureSite(env);
  const NO = { notice: { on: false, en: '', sw: '', level: 'info', from: '', to: '' }, contacts: { hidden: [], edits: {}, added: [] }, flags: {} };
  if (act === 'site/get' && method === 'GET') {
    const out = {};
    for (const k of Object.keys(NO)) out[k] = await read(env, k, NO[k]);
    const a = await env.DB.prepare('SELECT at, who, act, detail FROM site_audit ORDER BY id DESC LIMIT 60').all();
    return [200, { ok: true, settings: out, audit: a.results || [], pages: PUBLIC_PAGES }];
  }
  if (act === 'site/articles' && method === 'GET') {
    try { const rs = await env.DB.prepare('SELECT slug, title_en, county, date, status FROM articles ORDER BY date DESC, id DESC LIMIT 100').all(); return [200, { ok: true, rows: rs.results || [] }]; } catch (e) { return [200, { ok: true, rows: [] }]; }
  }
  if (method !== 'POST') return [405, { ok: false, error: 'method' }];
  if (act === 'site/notice') {
    const en = clean(body.en, 240), sw = clean(body.sw, 240), on = !!body.on && !!(en || sw);
    const v = { on, en, sw, level: body.level === 'warn' ? 'warn' : 'info', from: date(body.from), to: date(body.to) };
    await write(env, 'notice', v, actor, 'notice', on ? 'on: ' + (en || sw).slice(0, 80) : 'off');
    return [200, { ok: true, notice: v }];
  }
  if (act === 'site/flags') {
    const f = {}; for (const p of PUBLIC_PAGES) if (body && body.flags && body.flags[p] === false) f[p] = false;
    await write(env, 'flags', f, actor, 'pages', Object.keys(f).length ? 'off: ' + Object.keys(f).join(' ') : 'all on');
    return [200, { ok: true, flags: f }];
  }
  if (act === 'site/contacts') {
    const C = await read(env, 'contacts', NO.contacts); C.hidden = C.hidden || []; C.edits = C.edits || {}; C.added = C.added || [];
    const id = String((body && body.id) || '').replace(/[^a-z0-9-]/gi, '').slice(0, 70), op = body && body.op;
    if (op === 'hide' && id) { if (!C.hidden.includes(id) && C.hidden.length < 300) C.hidden.push(id); }
    else if (op === 'show' && id) C.hidden = C.hidden.filter((x) => x !== id);
    else if (op === 'edit' && id) { const c = cleanContact(body.contact, false); if (!c) return [400, { ok: false, error: 'contact' }]; if (Object.keys(C.edits).length >= 200 && !C.edits[id]) return [400, { ok: false, error: 'limit' }]; C.edits[id] = c; }
    else if (op === 'reset' && id) delete C.edits[id];
    else if (op === 'add') { if (C.added.length >= 100) return [400, { ok: false, error: 'limit' }]; const c = cleanContact({ ...(body.contact || {}), id: Date.now().toString(36) }, true); if (!c) return [400, { ok: false, error: 'contact' }]; C.added.push(c); }
    else if (op === 'remove' && id) C.added = C.added.filter((x) => x.id !== id);
    else return [400, { ok: false, error: 'op' }];
    await write(env, 'contacts', C, actor, 'contacts ' + op, id || (body.contact && body.contact.name) || '');
    return [200, { ok: true, contacts: C }];
  }
  if (act === 'site/article') {
    const slug = clean(body && body.slug, 120).toLowerCase(), st = body && body.status;
    if (!slug || !['published', 'draft'].includes(st)) return [400, { ok: false, error: 'bad' }];
    const r = await env.DB.prepare('UPDATE articles SET status=? WHERE slug=?').bind(st, slug).run();
    if (!(r.meta && r.meta.changes)) return [404, { ok: false, error: 'notfound' }];
    await env.DB.prepare(`INSERT INTO site_audit (at, who, act, detail) VALUES (${NOW},?,?,?)`).bind(actor, 'article ' + st, slug).run();
    return [200, { ok: true }];
  }
  return [404, { ok: false, error: 'notfound' }];
}
