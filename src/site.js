// Site settings for the public site, edited only by the super administrator on the admin subdomain. Stored in the shared D1 database;
// the public worker reads notice, contacts and flags (GET /api/site). Every change is written to an audit log.
const READY = new WeakSet();
export const PUBLIC_PAGES = ['/contacts/', '/trip/', '/print/', '/scam/', '/analysis/'];
export const SCOPES = ['notice', 'alert', 'contacts', 'articles', 'home', 'feedback', 'corrections', 'incidents'];
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
    env.DB.prepare('CREATE TABLE IF NOT EXISTS site_images (id INTEGER PRIMARY KEY AUTOINCREMENT, type TEXT, data TEXT, at TEXT, who TEXT)'),
    env.DB.prepare('CREATE TABLE IF NOT EXISTS page_hits (day TEXT, path TEXT, n INTEGER DEFAULT 0, PRIMARY KEY (day, path))'),
    env.DB.prepare('CREATE TABLE IF NOT EXISTS overlay (k TEXT PRIMARY KEY, v TEXT NOT NULL, at TEXT NOT NULL)'),
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
  contacts: { hidden: [], edits: {}, added: [], verified: {} },
  flags: {}, roles: { editors: [] }, schedule: {}, corrections: [], pending: [], pause: null, checks: null,
};
const SCOPE_OF = { notice: 'notice', alert: 'alert', home: 'home', contacts: 'contacts', corrections: 'corrections' };

const COUNTIES = ['Baringo','Bomet','Bungoma','Busia','Elgeyo-Marakwet','Embu','Garissa','Homa Bay','Isiolo','Kajiado','Kakamega','Kericho','Kiambu','Kilifi','Kirinyaga','Kisii','Kisumu','Kitui','Kwale','Laikipia','Lamu','Machakos','Makueni','Mandera','Marsabit','Meru','Migori','Mombasa',"Murang'a",'Nairobi','Nakuru','Nandi','Narok','Nyamira','Nyandarua','Nyeri','Samburu','Siaya','Taita Taveta','Tana River','Tharaka-Nithi','Trans Nzoia','Turkana','Uasin Gishu','Vihiga','Wajir','West Pokot'];
const INC_KINDS = ['crimes', 'attacks', 'road_crashes', 'banditry', 'reports'];
const sigOf = (k, r) => String(r.id || (r.date + '|' + (r.place || '') + '|' + String(r.summary || r.summary_en || '').slice(0, 40)));
const incRow = (k, r) => ({ k, sig: sigOf(k, r), id: r.id || '', date: r.date, county: r.county || '', place: r.place || '', text: String(r.summary || r.summary_en || '').slice(0, 220), by: r.by || '' });
async function ovRead(env, k) {
  const r = await env.DB.prepare('SELECT v FROM overlay WHERE k=?').bind(k).first();
  try { const a = JSON.parse(r && r.v); return Array.isArray(a) ? a : []; } catch (e) { return []; }
}
async function ovWrite(env, k, list, who, detail) {
  const old = await env.DB.prepare('SELECT v FROM overlay WHERE k=?').bind(k).first();
  await env.DB.batch([
    env.DB.prepare(`INSERT INTO site_versions (k, v, at, who) VALUES (?,?,${NOW},?)`).bind('overlay:' + k, (old && old.v) || '[]', who),
    env.DB.prepare(`INSERT INTO overlay (k, v, at) VALUES (?,?,${NOW}) ON CONFLICT(k) DO UPDATE SET v=excluded.v, at=excluded.at`).bind(k, JSON.stringify(list)),
    env.DB.prepare(`INSERT INTO site_audit (at, who, act, detail) VALUES (${NOW},?,?,?)`).bind(who, 'incident:' + k, String(detail).slice(0, 300)),
    env.DB.prepare('DELETE FROM site_versions WHERE k=? AND id NOT IN (SELECT id FROM site_versions WHERE k=? ORDER BY id DESC LIMIT 25)').bind('overlay:' + k, 'overlay:' + k),
  ]);
}
const num = (v) => { if (v === '' || v == null) return null; const n = Math.floor(Number(v)); return Number.isFinite(n) && n >= 0 && n < 100000 ? n : null; };
export function cleanIncident(k, b) {
  const county = COUNTIES.find((c) => c === (b && b.county)); const d = String((b && b.date) || '').slice(0, 10);
  if (!county || !date(d) || d > todayEAT()) return null;
  const en = clean(b.en, 600), sw = clean(b.sw, 600), place = clean(b.place, 120), link = b.link ? okUrl(clean(b.link, 300)) : '', source = clean(b.source, 80);
  if (en.length < 10 || (b.link && !link)) return null;
  const base = { date: d, county, place, link: link || null, source: source || null };
  if (k === 'reports') return { date: d, county, summary_en: en, summary_sw: sw || en };
  if (k === 'attacks') return { ...base, summary: en, precision: 'day' };
  if (k === 'road_crashes') return { ...base, summary: en, killed: num(b.killed), injured: num(b.injured) };
  if (k === 'banditry') return { ...base, summary_en: en, summary_sw: sw || en, kind_en: clean(b.kind, 40) || 'Raid', kind_sw: clean(b.kind, 40) || 'Uvamizi', killed: num(b.killed), stolen: num(b.stolen), recovered: num(b.recovered) };
  return { ...base, summary: en, kind: clean(b.kind, 60) || 'Crime', killed: num(b.killed), injured: num(b.injured) };
}
const QUEUE = ['site/notice', 'site/alert', 'site/home', 'site/contacts', 'site/article', 'site/article_save', 'site/schedule', 'site/correction', 'site/incident'];
const todayEAT = () => new Date(Date.now() + 3 * 3600e3).toISOString().slice(0, 10);
const nowEAT = () => new Date(Date.now() + 3 * 3600e3).toISOString().slice(0, 16);
const endOf = (v) => (v && v.length === 10 ? v + 'T23:59' : v);
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


const slugify = (t) => String(t || '').toLowerCase().normalize('NFKD').replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 70);
function okUrl(u) {
  try { const x = new URL(u); const h = x.hostname; return x.protocol === 'https:' && h.includes('.') && !/^[\d.]+$/.test(h) && !h.includes(':') && !/\.(local|internal|localhost|lan)$/.test(h) && !/^\[/.test(h) ? x.href : ''; } catch (e) { return ''; }
}
async function headStatus(u) { const { r, ms } = await fetchT(u, 5000); let st = r ? r.status : 0; if (r && (st === 405 || st === 403)) { const g = await fetchT(u, 5000); st = g.r ? g.r.status : 0; } return { status: st, ms }; }
export async function checkArticles(env) {
  await ensureSite(env);
  const rs = await env.DB.prepare('SELECT slug, body_en, body_sw FROM articles').all(); const seen = new Map();
  for (const a of rs.results || []) for (const m of (String(a.body_en || '') + ' ' + String(a.body_sw || '')).match(/https:\/\/[^\s<>"')\]]+/g) || []) { const u = okUrl(m.replace(/[.,;]+$/, '')); if (u && !seen.has(u) && seen.size < 30) seen.set(u, a.slug); }
  const res = await Promise.all([...seen].map(async ([u, slug]) => ({ url: u, slug, ...(await headStatus(u)) })));
  const v = { at: new Date().toISOString(), total: res.length, bad: res.filter((x) => !(x.status >= 200 && x.status < 400)).map((x) => ({ url: x.url, slug: x.slug, status: x.status })) };
  await env.DB.prepare(`INSERT INTO site_settings (k, v, at, by) VALUES ('checks',?,${NOW},'check') ON CONFLICT(k) DO UPDATE SET v=excluded.v, at=excluded.at, by=excluded.by`).bind(JSON.stringify(v)).run();
  return v;
}
// Runs from the cron trigger: publish or take down scheduled articles, and re-check article links about weekly.
export async function cron(env) {
  await applySchedule(env);
  const c = await read(env, 'checks', null);
  if (!c || Date.now() - Date.parse(c.at) > 6 * 864e5) await checkArticles(env);
}

// who = { email, super, scopes }. Returns [status, body].
async function inner(env, who, act, method, body) {
  await ensureSite(env);
  const actor = who.email;
  const ROOT = env.PUBLIC_ORIGIN || 'https://homesupport.co.ke';
  const need = (scope) => (allowed(who, scope) ? null : [403, { ok: false, error: 'scope' }]);
  if (act === 'site/get' && method === 'GET') {
    const out = {};
    await applySchedule(env);
    for (const k of Object.keys(DEF)) { if ((k === 'roles' || k === 'pending') && !who.super) continue; out[k] = await read(env, k, DEF[k]); }
    const a = await env.DB.prepare('SELECT at, who, act, detail FROM site_audit ORDER BY id DESC LIMIT 80').all();
    return [200, { ok: true, me: { email: actor, super: !!who.super, readonly: !!who.readonly, approval: !!who.approval, scopes: who.super ? SCOPES : who.scopes || [] }, settings: out, audit: a.results || [], pages: PUBLIC_PAGES }];
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
  if (act === 'site/article_get' && method === 'GET') {
    const bad = need('articles'); if (bad) return bad;
    const a = await env.DB.prepare('SELECT slug, title_en, title_sw, body_en, body_sw, county, date, status FROM articles WHERE slug=?').bind(clean(body && body.slug, 120).toLowerCase()).first();
    return a ? [200, { ok: true, article: a }] : [404, { ok: false, error: 'notfound' }];
  }
  if (act === 'site/images' && method === 'GET') {
    const bad = need('articles'); if (bad) return bad;
    const rs = await env.DB.prepare('SELECT id, type, at FROM site_images ORDER BY id DESC LIMIT 40').all(); return [200, { ok: true, rows: rs.results || [] }];
  }
  if (act === 'site/hits' && method === 'GET') {
    const t = await env.DB.prepare("SELECT path, SUM(n) n FROM page_hits WHERE day >= date('now','-30 day') GROUP BY path ORDER BY n DESC LIMIT 30").all();
    const d = await env.DB.prepare("SELECT day, SUM(n) n FROM page_hits WHERE day >= date('now','-13 day') GROUP BY day ORDER BY day").all();
    return [200, { ok: true, paths: t.results || [], days: d.results || [] }];
  }
  if (act === 'site/attention' && method === 'GET') {
    const out = [], add = (level, text, tab) => out.push({ level, text, tab });
    if (who.super) { const P = await read(env, 'pending', []); if (P.length) add('warn', P.length + ' change' + (P.length === 1 ? '' : 's') + ' waiting for your approval', 'approvals'); const pz = await read(env, 'pause', null); if (pz) add('warn', 'Emergency pause is ON: optional pages are switched off', 'overview'); }
    const al = await read(env, 'alert', DEF.alert); if (al.on && al.until) { const ms = Date.parse(endOf(al.until) + ':00+03:00') - Date.now(); if (ms < 0) add('info', 'The red alert strip is switched on but has expired. Switch it off.', 'notice'); else if (ms < 6 * 3600e3) add('warn', 'The red alert strip ends in under 6 hours', 'notice'); }
    const sc = await read(env, 'schedule', {}); if (Object.keys(sc).length) add('info', Object.keys(sc).length + ' article' + (Object.keys(sc).length === 1 ? '' : 's') + ' scheduled', 'articles');
    try { const f = await env.DB.prepare("SELECT COUNT(*) n FROM guide_feedback WHERE at >= date('now','-7 day')").first(); if (f && f.n) add('info', f.n + ' feedback message' + (f.n === 1 ? '' : 's') + ' in the last 7 days', 'feedback'); } catch (e) {}
    const ck = await read(env, 'checks', null); if (ck && ck.bad && ck.bad.length) add('warn', ck.bad.length + ' article link' + (ck.bad.length === 1 ? '' : 's') + ' not working (checked ' + ck.at.slice(0, 10) + ')', 'health');
    const C = await read(env, 'contacts', DEF.contacts); const old = new Date(Date.now() - 183 * 864e5).toISOString().slice(0, 10); const ver = C.verified || {};
    add('info', 'Contacts: ' + Object.keys(ver).length + ' marked verified; ' + Object.values(ver).filter((d) => d < old).length + ' older than 6 months', 'contacts');
    const { r } = await fetchT(ROOT + '/data/d.json');
    if (r && r.ok) { try { const d = await r.json(); const days = d._built ? Math.floor((Date.now() - Date.parse(d._built)) / 864e5) : null; if (days != null && days > 14) add('warn', 'Public data was last built ' + days + ' days ago', 'overview'); } catch (e) {} } else add('warn', 'Could not read the public data file', 'health');
    return [200, { ok: true, items: out }];
  }
  if (act === 'site/export' && method === 'GET') {
    if (!who.super) return [403, { ok: false, error: 'scope' }];
    const s = {}; for (const k of Object.keys(DEF)) if (k !== 'roles') s[k] = await read(env, k, DEF[k]);
    return [200, { ok: true, backup: { app: 'hapa-admin', v: 1, at: new Date().toISOString(), settings: s } }];
  }
  if (act === 'site/incidents' && method === 'GET') {
    const bad = need('incidents'); if (bad) return bad;
    const out = [];
    for (const k of INC_KINDS) { const L = await ovRead(env, k); L.forEach((r) => { if (r && r.date) out.push(incRow(k, r)); }); }
    out.sort((a, b) => (a.date < b.date ? 1 : a.date > b.date ? -1 : 0));
    return [200, { ok: true, rows: out.slice(0, 60), counties: COUNTIES }];
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
    const C = await read(env, 'contacts', DEF.contacts); C.hidden = C.hidden || []; C.edits = C.edits || {}; C.added = C.added || []; C.verified = C.verified || {};
    const idc = (x) => String(x || '').replace(/[^a-z0-9-]/gi, '').slice(0, 70);
    const id = idc(body && body.id), op = body && body.op;
    if (op === 'hide' && id) { if (!C.hidden.includes(id) && C.hidden.length < 300) C.hidden.push(id); }
    else if (op === 'show' && id) C.hidden = C.hidden.filter((x) => x !== id);
    else if ((op === 'hide_many' || op === 'show_many') && Array.isArray(body.ids)) {
      const ids = body.ids.map(idc).filter(Boolean).slice(0, 300);
      if (op === 'hide_many') { for (const x of ids) if (!C.hidden.includes(x)) C.hidden.push(x); if (C.hidden.length > 300) return [400, { ok: false, error: 'limit' }]; } else C.hidden = C.hidden.filter((x) => !ids.includes(x));
    }
    else if ((op === 'verify' || op === 'unverify') && Array.isArray(body.ids)) { for (const x of body.ids.map(idc).filter(Boolean).slice(0, 300)) { if (op === 'verify') C.verified[x] = todayEAT(); else delete C.verified[x]; } if (Object.keys(C.verified).length > 600) return [400, { ok: false, error: 'limit' }]; }
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
  if (act === 'site/article_save') {
    const bad = need('articles'); if (bad) return bad;
    const b = body || {}, t_en = clean(b.title_en, 160), t_sw = clean(b.title_sw, 160);
    const bd = (v) => String(v == null ? '' : v).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, '').replace(/\r/g, '').trim().slice(0, 20000);
    if (!t_en || !bd(b.body_en)) return [400, { ok: false, error: 'article' }];
    const dt = /^\d{4}-\d{2}-\d{2}$/.test(String(b.date || '')) ? b.date : todayEAT(), county = clean(b.county, 30);
    let slug = clean(b.slug, 90).toLowerCase();
    if (slug) {
      if (!slugOk(slug)) return [400, { ok: false, error: 'article' }];
      const r = await env.DB.prepare('UPDATE articles SET title_en=?, title_sw=?, body_en=?, body_sw=?, county=?, date=? WHERE slug=?').bind(t_en, t_sw, bd(b.body_en), bd(b.body_sw), county, dt, slug).run();
      if (!(r.meta && r.meta.changes)) return [404, { ok: false, error: 'notfound' }];
    } else {
      const base = slugify(t_en) || 'article'; slug = base.length < 3 ? base + '-post' : base;
      for (let i = 2; await env.DB.prepare('SELECT 1 x FROM articles WHERE slug=?').bind(slug).first(); i++) slug = base + '-' + i;
      await env.DB.prepare("INSERT INTO articles (slug, title_en, title_sw, body_en, body_sw, county, date, status) VALUES (?,?,?,?,?,?,?,'draft')").bind(slug, t_en, t_sw, bd(b.body_en), bd(b.body_sw), county, dt).run();
    }
    await env.DB.prepare(`INSERT INTO site_audit (at, who, act, detail) VALUES (${NOW},?,?,?)`).bind(actor, 'article saved', slug).run();
    return [200, { ok: true, slug }];
  }
  if (act === 'site/schedule') {
    const bad = need('articles'); if (bad) return bad;
    const slug = clean(body && body.slug, 120).toLowerCase(); if (!slugOk(slug) || !(await env.DB.prepare('SELECT 1 x FROM articles WHERE slug=?').bind(slug).first())) return [404, { ok: false, error: 'notfound' }];
    const S = await read(env, 'schedule', {}), at = date(body.at), off = date(body.off);
    if ((at && at.length === 10 ? at + 'T00:00' : at) && off && endOf(off) <= (at.length === 10 ? at + 'T00:00' : at)) return [400, { ok: false, error: 'order' }];
    if (!at && !off) delete S[slug]; else { if (Object.keys(S).length >= 50 && !S[slug]) return [400, { ok: false, error: 'limit' }]; S[slug] = { at, off }; }
    await write(env, 'schedule', S, actor, 'schedule', slug + (at ? ' publish ' + at : '') + (off ? ' off ' + off : '') + (!at && !off ? ' cleared' : ''));
    await applySchedule(env);
    return [200, { ok: true, schedule: await read(env, 'schedule', {}) }];
  }
  if (act === 'site/image') {
    const bad = need('articles'); if (bad) return bad;
    const d = String((body && body.data) || ''), type = d.startsWith('/9j/') ? 'image/jpeg' : d.startsWith('iVBOR') ? 'image/png' : '';
    if (!type || !/^[A-Za-z0-9+/=]+$/.test(d) || d.length > 700000) return [400, { ok: false, error: 'image' }];
    const n = (await env.DB.prepare('SELECT COUNT(*) n FROM site_images').first()).n; if (n >= 150) return [400, { ok: false, error: 'limit' }];
    const r = await env.DB.prepare(`INSERT INTO site_images (type, data, at, who) VALUES (?,?,${NOW},?)`).bind(type, d, actor).run();
    const id = r.meta && (r.meta.last_row_id || r.meta.lastRowId);
    await env.DB.prepare(`INSERT INTO site_audit (at, who, act, detail) VALUES (${NOW},?,?,?)`).bind(actor, 'image uploaded', '#' + id).run();
    return [200, { ok: true, id, tag: '[img:' + id + ']' }];
  }
  if (act === 'site/correction') {
    const bad = need('corrections'); if (bad) return bad;
    const L = await read(env, 'corrections', []), op = body && body.op;
    if (op === 'add') {
      const en = clean(body.en, 400), sw = clean(body.sw, 400), dt = date(body.date) || todayEAT(), link = body.link ? okUrl(clean(body.link, 300)) : '';
      if (!en || (body.link && !link)) return [400, { ok: false, error: 'correction' }]; if (L.length >= 100) return [400, { ok: false, error: 'limit' }];
      L.unshift({ id: Date.now().toString(36), date: dt.slice(0, 10), en, sw, link });
    } else if (op === 'remove') { const i = L.findIndex((x) => x.id === (body && body.id)); if (i < 0) return [404, { ok: false, error: 'notfound' }]; L.splice(i, 1); } else return [400, { ok: false, error: 'op' }];
    await write(env, 'corrections', L, actor, 'correction ' + op, (body.en || body.id || '').slice(0, 80));
    return [200, { ok: true, corrections: L }];
  }
  if (act === 'site/checklink') {
    if (!who.super && !(who.scopes || []).some((x) => ['articles', 'corrections'].includes(x))) return [403, { ok: false, error: 'scope' }];
    const u = okUrl(clean(body && body.url, 400)); if (!u) return [400, { ok: false, error: 'url' }];
    return [200, { ok: true, ...(await headStatus(u)) }];
  }
  if (act === 'site/checkarticles') { const bad = need('articles'); if (bad) return bad; return [200, { ok: true, checks: await checkArticles(env) }]; }
  if (act === 'site/pause') {
    if (!who.super) return [403, { ok: false, error: 'scope' }];
    if (body && body.on) {
      const snap = { flags: await read(env, 'flags', {}), notice: await read(env, 'notice', DEF.notice) }; const f = {}; for (const p of PUBLIC_PAGES) f[p] = false;
      if (!(await read(env, 'pause', null))) await write(env, 'pause', { at: new Date().toISOString(), snap }, actor, 'EMERGENCY PAUSE', 'on');
      await write(env, 'flags', f, actor, 'pause', 'all optional pages off');
      await write(env, 'notice', { on: true, en: clean(body.en, 240) || 'Some pages are paused while we check them. Emergency numbers on the Emergency page stay available.', sw: clean(body.sw, 240) || 'Baadhi ya kurasa zimesimamishwa kwa muda tunapozikagua. Nambari za dharura kwenye ukurasa wa Dharura zinaendelea kupatikana.', level: 'warn', from: '', to: '' }, actor, 'pause', 'notice on');
    } else {
      const pz = await read(env, 'pause', null); if (!pz) return [400, { ok: false, error: 'notpaused' }];
      await write(env, 'flags', pz.snap.flags, actor, 'resume', 'pages restored'); await write(env, 'notice', pz.snap.notice, actor, 'resume', 'notice restored'); await write(env, 'pause', null, actor, 'RESUME', 'off');
    }
    return [200, { ok: true, pause: await read(env, 'pause', null) }];
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
      if (!EMAIL.test(email) || seen.has(email) || !scopes.length) continue; seen.add(email); editors.push({ email, scopes, approval: !!(e && e.approval), readonly: !!(e && e.readonly) });
    }
    await write(env, 'roles', { editors }, actor, 'roles', editors.map((e) => e.email + ' [' + e.scopes.join(',') + (e.approval ? ',approval' : '') + (e.readonly ? ',readonly' : '') + ']').join('; ') || 'none');
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
      const c = s.contacts, C = { hidden: [], edits: {}, added: [], verified: {} };
      C.verified = {}; for (const [id, d] of Object.entries(c.verified || {}).slice(0, 600)) if (/^\d{4}-\d{2}-\d{2}$/.test(String(d))) C.verified[String(id).replace(/[^a-z0-9-]/gi, '').slice(0, 70)] = d;
      C.hidden = (Array.isArray(c.hidden) ? c.hidden : []).map((x) => String(x).replace(/[^a-z0-9-]/gi, '').slice(0, 70)).filter(Boolean).slice(0, 300);
      for (const [id, v] of Object.entries(c.edits || {}).slice(0, 200)) { const cc = cleanContact(v, false); if (cc) C.edits[String(id).replace(/[^a-z0-9-]/gi, '').slice(0, 70)] = cc; }
      for (const v of (Array.isArray(c.added) ? c.added : []).slice(0, 100)) { const cc = cleanContact(v, true); if (cc) C.added.push(cc); }
      await write(env, 'contacts', C, actor, 'import', 'contacts'); done.push('contacts');
    }
    return [200, { ok: true, done }];
  }

  if (act === 'site/incident') {
    const bad = need('incidents'); if (bad) return bad;
    const op = body && body.op, k = body && body.k;
    if (!INC_KINDS.includes(k)) return [400, { ok: false, error: 'kind' }];
    const L = await ovRead(env, k);
    if (op === 'add') {
      const r = cleanIncident(k, body);
      if (!r) return [400, { ok: false, error: 'incident' }];
      if (L.length >= 2000) return [400, { ok: false, error: 'limit' }];
      r.id = 'a' + Date.now().toString(36); r.by = actor.slice(0, 80);
      L.unshift(r);
      await ovWrite(env, k, L, actor, 'added: ' + r.county + ' ' + r.date);
      return [200, { ok: true }];
    }
    if (op === 'remove') {
      const i = L.findIndex((r) => r && sigOf(k, r) === body.sig);
      if (i < 0) return [404, { ok: false, error: 'notfound' }];
      const [r] = L.splice(i, 1);
      await ovWrite(env, k, L, actor, 'removed: ' + (r.county || '') + ' ' + (r.date || ''));
      return [200, { ok: true }];
    }
    return [400, { ok: false, error: 'op' }];
  }
  return [404, { ok: false, error: 'notfound' }];
}

// ---- wrapper: read-only role, approval queue ----
export async function siteApi(env, who, act, method, body) {
  await ensureSite(env);
  if (method === 'POST' && !who.super) {
    if (who.readonly) return [403, { ok: false, error: 'readonly' }];
    if (who.approval && QUEUE.includes(act)) {
      const P = await read(env, 'pending', []);
      if (P.length >= 30) return [400, { ok: false, error: 'limit' }];
      P.push({ id: Date.now().toString(36) + Math.floor(Math.random() * 1e4).toString(36), at: new Date().toISOString(), who: who.email, act, body });
      await write(env, 'pending', P, who.email, 'queued for approval', act);
      return [202, { ok: true, pending: true }];
    }
  }
  if (method === 'POST' && !who.super && (act === 'site/approve' || act === 'site/reject')) return [403, { ok: false, error: 'scope' }];
  if (method === 'POST' && who.super && (act === 'site/approve' || act === 'site/reject')) {
    const P = await read(env, 'pending', []), i = P.findIndex((x) => x.id === (body && body.id));
    if (i < 0) return [404, { ok: false, error: 'notfound' }];
    const [it] = P.splice(i, 1);
    if (act === 'site/approve') {
      const [st, js] = await inner(env, { email: it.who + ' (approved by ' + who.email + ')', super: true, scopes: [] }, it.act, 'POST', it.body);
      if (st >= 300) return [st, js];
    }
    await write(env, 'pending', P, who.email, act === 'site/approve' ? 'approved' : 'rejected', it.act + ' from ' + it.who);
    return [200, { ok: true, pending: P }];
  }
  return inner(env, who, act, method, body);
}

// ---- scheduled publishing (run by the cron trigger and whenever Admin loads) ----
export async function applySchedule(env) {
  await ensureSite(env);
  const S = await read(env, 'schedule', {}), now = nowEAT(); let ch = false;
  for (const [slug, v] of Object.entries(S)) {
    if (v.at && endOf(v.at) <= now && !v.done) { await env.DB.prepare("UPDATE articles SET status='published' WHERE slug=?").bind(slug).run(); v.done = true; ch = true; await env.DB.prepare(`INSERT INTO site_audit (at, who, act, detail) VALUES (${NOW},?,?,?)`).bind('schedule', 'article published', slug).run(); }
    if (v.off && v.off <= now && !v.offdone) { await env.DB.prepare("UPDATE articles SET status='draft' WHERE slug=?").bind(slug).run(); v.offdone = true; ch = true; await env.DB.prepare(`INSERT INTO site_audit (at, who, act, detail) VALUES (${NOW},?,?,?)`).bind('schedule', 'article taken down', slug).run(); }
    if ((!v.at || v.done) && (!v.off || v.offdone)) { delete S[slug]; ch = true; }
  }
  if (ch) await env.DB.prepare(`INSERT INTO site_settings (k, v, at, by) VALUES ('schedule',?,${NOW},'schedule') ON CONFLICT(k) DO UPDATE SET v=excluded.v, at=excluded.at, by=excluded.by`).bind(JSON.stringify(S)).run();
}
