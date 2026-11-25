import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import worker from '../src/worker.js';
import { cleanContact, cleanNums } from '../src/site.js';

function fakeD1() {
  const db = new DatabaseSync(':memory:');
  db.exec("CREATE TABLE ops_events (id INTEGER PRIMARY KEY AUTOINCREMENT, agency TEXT, category TEXT, date TEXT, county TEXT, subcounty TEXT, place TEXT, arrests INT, fines INT, quantity REAL, unit TEXT, note TEXT, created TEXT, code_id INT, src TEXT)");
  db.exec("CREATE TABLE codes (id INTEGER PRIMARY KEY, h TEXT, label TEXT, hint TEXT, agency TEXT, email TEXT, plan TEXT, expires TEXT, revoked INT DEFAULT 0, created TEXT, last_used TEXT, uses INT DEFAULT 0, role TEXT DEFAULT 'full', ack TEXT); CREATE TABLE sessions (th TEXT, code_id INT, at TEXT); CREATE TABLE attempts (ip TEXT, at TEXT)");
  const mk = (sql, args = []) => ({ bind: (...a) => mk(sql, a), run: async () => { const r = db.prepare(sql).run(...args); return { meta: { changes: r.changes, last_row_id: Number(r.lastInsertRowid) } }; }, first: async () => db.prepare(sql).get(...args) || null, all: async () => ({ results: db.prepare(sql).all(...args) }) });
  const o = { db, prepare: (s) => mk(s), batch: async (xs) => { const r = []; for (const x of xs) r.push(await x.run()); return r; } }; o.DB = o; return o;
}

const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'k1', alg: 'RS256', use: 'sig' };
const realFetch = globalThis.fetch;
globalThis.fetch = async (u, o) => (String(u).startsWith('https://team.cloudflareaccess.com/cdn-cgi/access/certs') ? new Response(JSON.stringify({ keys: [jwk] })) : realFetch(u, o));
const b64u = (b) => Buffer.from(b).toString('base64url');
function token(over = {}, key = privateKey) {
  const h = b64u(JSON.stringify({ alg: 'RS256', kid: 'k1' })), p = b64u(JSON.stringify({ aud: ['AUD1'], iss: 'https://team.cloudflareaccess.com', exp: Math.floor(Date.now() / 1000) + 600, email: 'masaikta@gmail.com', ...over }));
  return h + '.' + p + '.' + b64u(crypto.sign('RSA-SHA256', Buffer.from(h + '.' + p), key));
}
const mkenv = () => { const e = fakeD1(); e.ACCESS_TEAM = 'team'; e.ACCESS_AUD = 'AUD1'; e.ASSETS = { fetch: async () => new Response('<html>page</html>', { headers: { 'content-type': 'text/html' } }) }; return e; };
const call = (env, jwt) => async (path, body, method = 'POST') => {
  const headers = { 'content-type': 'application/json', ...(jwt ? { 'cf-access-jwt-assertion': jwt } : {}) };
  const r = await worker.fetch(new Request('https://admin.homesupport.co.ke' + path, { method, headers, body: method === 'POST' ? JSON.stringify(body || {}) : undefined }), env);
  const txt = await r.text(); let json = null; try { json = JSON.parse(txt); } catch (e) {} return { status: r.status, json, txt };
};
test('validation: contacts and numbers', () => {
  assert.deepEqual(cleanNums(['0711 222 333', 'wa:+254700111222', 'drop table', '<b>1</b>']), ['0711 222 333', 'wa:+254700111222']);
  assert.equal(cleanContact({ name: 'Clinic', nums: ['999'] }, false).name, 'Clinic');
  assert.equal(cleanContact({ name: '', nums: ['999'] }, false), null);
  assert.equal(cleanContact({ name: 'X', nums: ['abc'] }, false), null);
  assert.equal(cleanContact({ name: 'X', nums: ['999'], cat: 'bogus' }, true), null);
});
test('access: closed until configured, and only a genuine token for the super administrator gets in', async () => {
  const env = mkenv();
  const none = fakeD1(); assert.equal((await call(none, token())('/api/site/get', null, 'GET')).status, 503, 'refuses everything until Access settings exist');
  assert.equal((await call(env, '')('/api/site/get', null, 'GET')).status, 403, 'no token');
  assert.equal((await call(env, 'a.b.c')('/api/site/get', null, 'GET')).status, 403, 'garbage token');
  const other = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  assert.equal((await call(env, token({}, other.privateKey))('/api/site/get', null, 'GET')).status, 403, 'forged signature');
  assert.equal((await call(env, token({ aud: ['OTHER'] }))('/api/site/get', null, 'GET')).status, 403, 'token for another application');
  assert.equal((await call(env, token({ exp: 1 }))('/api/site/get', null, 'GET')).status, 403, 'expired');
  assert.equal((await call(env, token({ email: 'other@example.com' }))('/api/site/get', null, 'GET')).status, 404, 'a different person is turned away');
  assert.equal((await call(env, token())('/api/site/get', null, 'GET')).status, 200);
  assert.equal((await call(env, token())('/', null, 'GET')).txt, '<html>page</html>');
  const bad = await worker.fetch(new Request('https://admin.homesupport.co.ke/api/site/notice', { method: 'POST', headers: { 'content-type': 'text/plain', 'cf-access-jwt-assertion': token() }, body: '{}' }), env); assert.equal(bad.status, 415);
  const cross = await worker.fetch(new Request('https://admin.homesupport.co.ke/api/site/notice', { method: 'POST', headers: { 'content-type': 'application/json', origin: 'https://evil.example', 'cf-access-jwt-assertion': token() }, body: '{}' }), env); assert.equal(cross.status, 403);
});
test('site settings: saved, validated and logged', async () => {
  const env = mkenv();
  env.db.exec("CREATE TABLE articles (id INTEGER PRIMARY KEY, slug TEXT, title_en TEXT, title_sw TEXT, body_en TEXT, county TEXT, date TEXT, status TEXT)");
  env.db.exec("INSERT INTO articles (slug,title_en,status,date) VALUES ('a-one','One','published','2026-11-01')");
  const S = call(env, token());
  const n = (await S('/api/site/notice', { on: true, en: 'Heavy rain <script>', sw: '', level: 'warn', from: '2026-11-01', to: 'junk' })).json.notice;
  assert.equal(n.on, true); assert.ok(!n.en.includes('<')); assert.equal(n.to, ''); assert.equal(n.level, 'warn');
  assert.equal((await S('/api/site/notice', { on: true, en: '', sw: '' })).json.notice.on, false, 'an empty notice is off');
  assert.deepEqual((await S('/api/site/flags', { flags: { '/contacts/': false, '/admin/': false, '/trip/': true } })).json.flags, { '/contacts/': false }, 'only known pages');
  assert.deepEqual((await S('/api/site/contacts', { op: 'hide', id: 'em-x' })).json.contacts.hidden, ['em-x']);
  assert.equal((await S('/api/site/contacts', { op: 'edit', id: 'abc', contact: { name: 'New name', nums: ['0711 222 333'] } })).json.contacts.edits.abc.name, 'New name');
  assert.equal((await S('/api/site/contacts', { op: 'edit', id: 'abc', contact: { name: 'No number', nums: [] } })).status, 400);
  const add = (await S('/api/site/contacts', { op: 'add', contact: { name: 'Mercy Clinic', cat: 'hosp', county: 'Nakuru', nums: ['0700 111 222'] } })).json.contacts.added;
  assert.equal(add.length, 1); assert.match(add[0].id, /^x-/);
  assert.equal((await S('/api/site/contacts', { op: 'add', contact: { name: 'Bad', cat: 'bogus', nums: ['999'] } })).status, 400);
  assert.equal((await S('/api/site/contacts', { op: 'remove', id: add[0].id })).json.contacts.added.length, 0);
  assert.equal((await S('/api/site/article', { slug: 'a-one', status: 'draft' })).status, 200);
  assert.equal(env.db.prepare("SELECT status FROM articles WHERE slug='a-one'").get().status, 'draft');
  assert.equal((await S('/api/site/article', { slug: 'missing', status: 'draft' })).status, 404);
  assert.equal((await S('/api/site/pro', { links: false })).status, 404, 'no Pro settings here');
  const g = (await S('/api/site/get', null, 'GET')).json; assert.ok(g.audit.length >= 8); assert.ok(g.audit.every((a) => a.who === 'masaikta@gmail.com'));
  assert.deepEqual(g.settings.flags, { '/contacts/': false }); assert.equal('pro' in g.settings, false);
});
test('versions, restore, alert expiry, home, roles, backup', async () => {
  const env = mkenv(); const S = call(env, token());
  await S('/api/site/notice', { on: true, en: 'First' }); await S('/api/site/notice', { on: true, en: 'Second', from: '2026-11-13T08:30' });
  const v = (await S('/api/site/versions?k=notice', null, 'GET')).json.rows; assert.equal(v.length, 2); assert.equal(v[0].v.en, 'Second'); assert.equal(v[0].v.from, '2026-11-13T08:30');
  await S('/api/site/restore', { id: v[1].id }); assert.equal((await S('/api/site/get', null, 'GET')).json.settings.notice.en, 'First');
  assert.equal((await S('/api/site/alert', { on: true, en: 'Flood' })).status, 400, 'alert needs an end time');
  assert.equal((await S('/api/site/alert', { on: true, en: 'Flood', until: '2026-11-14T18:00' })).json.alert.until, '2026-11-14T18:00');
  const h = (await S('/api/site/home', { h_en: 'Hi <b>', keys: [{ n: '999', l_en: 'Police' }, { n: 'x', l_en: 'Bad' }], featured: ['Good-Slug', 'bad slug!', 'good-slug'] })).json.home;
  assert.equal(h.keys.length, 1); assert.deepEqual(h.featured, ['good-slug']); assert.ok(!h.h_en.includes('<'));
  assert.equal((await S('/api/site/contacts', { op: 'hide_many', ids: ['a', 'b'] })).json.contacts.hidden.length, 2);
  // second admin with limited scope
  await S('/api/site/roles', { editors: [{ email: 'Ed@X.com', scopes: ['notice', 'bogus'] }, { email: 'nope', scopes: ['notice'] }] });
  assert.deepEqual((await S('/api/site/get', null, 'GET')).json.settings.roles.editors, [{ email: 'ed@x.com', scopes: ['notice'], approval: false, readonly: false }]);
  const E = call(env, token({ email: 'ed@x.com' }));
  assert.equal((await E('/api/site/notice', { on: false })).status, 200);
  assert.equal((await E('/api/site/contacts', { op: 'hide', id: 'a' })).status, 403);
  assert.equal((await E('/api/site/flags', { flags: {} })).status, 403); assert.equal((await E('/api/site/roles', { editors: [] })).status, 403); assert.equal((await E('/api/site/export', null, 'GET')).status, 403);
  assert.equal((await E('/api/site/get', null, 'GET')).json.settings.roles, undefined);
  assert.equal((await call(env, token({ email: 'stranger@x.com' }))('/api/site/get', null, 'GET')).status, 404);
  // backup round trip
  const bk = (await S('/api/site/export', null, 'GET')).json.backup; await S('/api/site/notice', { on: true, en: 'Changed' });
  assert.deepEqual((await S('/api/site/import', { backup: bk })).json.done.sort(), ['alert', 'contacts', 'home', 'notice', 'pages']);
  assert.equal((await S('/api/site/get', null, 'GET')).json.settings.notice.en, bk.settings.notice.en);
  assert.equal((await S('/api/site/import', { backup: { app: 'x' } })).status, 400);
});
test('draft preview link: made for an existing article, scoped, stored with an expiry', async () => {
  const env = mkenv(); env.db.exec("CREATE TABLE articles (id INTEGER PRIMARY KEY, slug TEXT, title_en TEXT, title_sw TEXT, body_en TEXT, county TEXT, date TEXT, status TEXT)"); env.db.exec("INSERT INTO articles (slug,title_en,status) VALUES ('draft-one','D','draft')");
  const S = call(env, token()); const r = (await S('/api/site/preview', { slug: 'draft-one' })).json;
  assert.match(r.url, /^https:\/\/homesupport\.co\.ke\/a\/draft-one\?preview=[a-f0-9]{32}$/);
  const m = JSON.parse(env.db.prepare("SELECT v FROM site_settings WHERE k='previews'").get().v); const t = Object.values(m)[0]; assert.equal(t.slug, 'draft-one'); assert.ok(t.exp > Date.now() && t.exp < Date.now() + 3 * 3600e3);
  assert.equal((await S('/api/site/preview', { slug: 'missing-one' })).status, 404);
  await S('/api/site/roles', { editors: [{ email: 'ed@x.com', scopes: ['notice'] }] }); assert.equal((await call(env, token({ email: 'ed@x.com' }))('/api/site/preview', { slug: 'draft-one' })).status, 403);
});

test('article editor, scheduling, images, corrections, pause, verified, approvals and read-only', async () => {
  const env = mkenv(); env.db.exec("CREATE TABLE articles (id INTEGER PRIMARY KEY, slug TEXT, title_en TEXT, title_sw TEXT, body_en TEXT, body_sw TEXT, county TEXT, date TEXT, status TEXT)");
  const S = call(env, token());
  const a = (await S('/api/site/article_save', { title_en: 'Road safety: Nairobi', body_en: 'Para one\n\nPara two', county: 'Nairobi' })).json; assert.equal(a.slug, 'road-safety-nairobi');
  assert.equal((await S('/api/site/article_save', { title_en: 'Road safety: Nairobi', body_en: 'x' })).json.slug, 'road-safety-nairobi-2', 'slug collisions get a suffix');
  assert.equal(env.db.prepare("SELECT status FROM articles WHERE slug='road-safety-nairobi'").get().status, 'draft', 'new articles are drafts');
  assert.equal((await S('/api/site/article_save', { title_en: '', body_en: 'x' })).status, 400);
  await S('/api/site/article_save', { slug: a.slug, title_en: 'Road safety', body_en: 'Edited', date: '2026-11-12' }); assert.equal((await S('/api/site/article_get?slug=' + a.slug, null, 'GET')).json.article.body_en, 'Edited');
  // schedule: past publish time goes live straight away, then the entry clears
  await S('/api/site/schedule', { slug: a.slug, at: '2020-01-01T08:00' }); assert.equal(env.db.prepare("SELECT status FROM articles WHERE slug=?").get(a.slug).status, 'published');
  await S('/api/site/schedule', { slug: a.slug, at: '2099-01-01T08:00' }); assert.equal(JSON.parse(env.db.prepare("SELECT v FROM site_settings WHERE k='schedule'").get().v)[a.slug].at, '2099-01-01T08:00');
  assert.equal((await S('/api/site/schedule', { slug: a.slug, at: '2099-01-02T08:00', off: '2099-01-01T08:00' })).status, 400, 'take-down must be after publish');
  // images: only real jpeg/png, size limited
  assert.equal((await S('/api/site/image', { data: '/9j/4AAQSkZJRg==' })).json.tag, '[img:1]'); assert.equal((await S('/api/site/image', { data: 'PHNjcmlwdD4=' })).status, 400); assert.equal((await S('/api/site/image', { data: '/9j/' + 'A'.repeat(700000) })).status, 400);
  // thumbnails: an article can carry one of the uploaded image ids, shown once the article is reloaded, cleared by saving with none
  assert.equal((await S('/api/site/article_save', { slug: a.slug, title_en: 'Road safety', body_en: 'Edited', date: '2026-11-12', thumb_id: 1 })).json.ok, true);
  assert.equal((await S('/api/site/article_get?slug=' + a.slug, null, 'GET')).json.article.thumb_id, 1);
  assert.equal((await S('/api/site/article_save', { slug: a.slug, title_en: 'Road safety', body_en: 'Edited', date: '2026-11-12', thumb_id: 999 })).status, 400, 'an image id that was never uploaded is rejected');
  assert.equal((await S('/api/site/article_save', { slug: a.slug, title_en: 'Road safety', body_en: 'Edited', date: '2026-11-12' })).json.ok, true);
  assert.equal((await S('/api/site/article_get?slug=' + a.slug, null, 'GET')).json.article.thumb_id, null, 'omitting thumb_id clears it, matching the full-form save used elsewhere');
  // corrections and link check guard
  const c = (await S('/api/site/correction', { op: 'add', en: 'Fixed a date <b>', link: 'https://example.com/x' })).json.corrections; assert.equal(c.length, 1); assert.ok(!c[0].en.includes('<'));
  assert.equal((await S('/api/site/correction', { op: 'add', en: 'x', link: 'javascript:alert(1)' })).status, 400);
  assert.equal((await S('/api/site/checklink', { url: 'http://192.168.0.1/' })).status, 400); assert.equal((await S('/api/site/checklink', { url: 'https://localhost/' })).status, 400); assert.equal((await S('/api/site/checklink', { url: 'https://[::1]/' })).status, 400);
  // verified dates
  assert.equal((await S('/api/site/contacts', { op: 'verify', ids: ['a', 'b'] })).json.contacts.verified.a.length, 10); assert.equal(Object.keys((await S('/api/site/contacts', { op: 'unverify', ids: ['a'] })).json.contacts.verified).length, 1);
  // emergency pause and resume restore what was there before
  await S('/api/site/flags', { flags: { '/trip/': false } }); await S('/api/site/notice', { on: true, en: 'Mine' });
  const p = await S('/api/site/pause', { on: true }); assert.ok(p.json.pause); let g = (await S('/api/site/get', null, 'GET')).json.settings; assert.equal(Object.keys(g.flags).length, 5); assert.equal(g.notice.level, 'warn');
  await S('/api/site/pause', { on: false }); g = (await S('/api/site/get', null, 'GET')).json.settings; assert.deepEqual(g.flags, { '/trip/': false }); assert.equal(g.notice.en, 'Mine'); assert.equal(g.pause, null);
  // approvals: a second admin's change waits; reject discards; approve applies
  await S('/api/site/roles', { editors: [{ email: 'ed@x.com', scopes: ['notice'], approval: true }, { email: 'view@x.com', scopes: ['notice'], readonly: true }] });
  const E = call(env, token({ email: 'ed@x.com' })); const q = await E('/api/site/notice', { on: true, en: 'Needs approval' }); assert.equal(q.status, 202);
  assert.equal((await S('/api/site/get', null, 'GET')).json.settings.notice.en, 'Mine', 'not live yet'); const pend = (await S('/api/site/get', null, 'GET')).json.settings.pending; assert.equal(pend.length, 1);
  assert.equal((await E('/api/site/approve', { id: pend[0].id })).status, 403, 'a second admin cannot approve');
  await S('/api/site/approve', { id: pend[0].id }); assert.equal((await S('/api/site/get', null, 'GET')).json.settings.notice.en, 'Needs approval');
  await E('/api/site/notice', { on: true, en: 'Bad one' }); const p2 = (await S('/api/site/get', null, 'GET')).json.settings.pending; await S('/api/site/reject', { id: p2[0].id }); assert.equal((await S('/api/site/get', null, 'GET')).json.settings.notice.en, 'Needs approval');
  const V = call(env, token({ email: 'view@x.com' })); assert.equal((await V('/api/site/notice', { on: false })).status, 403); assert.equal((await V('/api/site/get', null, 'GET')).status, 200);
  assert.ok((await S('/api/site/attention', null, 'GET')).json.items.length > 0); assert.equal((await S('/api/site/hits', null, 'GET')).json.ok, true);
  // approval does not widen scope: an editor whose only scope is "notice" cannot even queue a contacts change
  assert.equal((await E('/api/site/contacts', { op: 'hide', id: 'x-1' })).status, 403, 'approval flag is not a free pass to other areas');
  assert.equal((await S('/api/site/get', null, 'GET')).json.settings.pending.length, 0, 'nothing was queued');
});

test('incidents: added to the shared overlay, validated, listed, removable, versioned', async () => {
  const env = mkenv(); const S = call(env, token());
  env.db.exec("CREATE TABLE overlay (k TEXT PRIMARY KEY, v TEXT NOT NULL, at TEXT NOT NULL)");
  env.db.prepare("INSERT INTO overlay (k,v,at) VALUES ('crimes',?,?)").run(JSON.stringify([{ date: '2026-11-01', county: 'Nairobi', place: 'Ruai', summary: 'Old crime item here' }]), '2026-11-07T00:00:00Z');
  const today = new Date(Date.now() + 3 * 3600e3).toISOString().slice(0, 10);
  const ok = await S('/api/site/incident', { op: 'add', k: 'crimes', county: 'Kilifi', date: today, place: 'Mtwapa <b>', en: 'Two suspects arrested over a robbery', killed: '0', link: 'https://example.com/a' });
  assert.equal(ok.status, 200);
  const rows = JSON.parse(env.db.prepare("SELECT v FROM overlay WHERE k='crimes'").get().v);
  assert.equal(rows.length, 2, 'existing rows kept'); assert.equal(rows[0].county, 'Kilifi'); assert.ok(!rows[0].place.includes('<')); assert.match(rows[0].id, /^a/);
  assert.equal(env.db.prepare("SELECT count(*) n FROM site_versions WHERE k='overlay:crimes'").get().n, 1, 'previous list saved for undo');
  for (const bad of [{ county: 'Atlantis' }, { date: '2099-01-01' }, { en: 'short' }, { link: 'javascript:alert(1)' }]) assert.equal((await S('/api/site/incident', { op: 'add', k: 'crimes', county: 'Kilifi', date: today, en: 'A long enough description', ...bad })).status, 400);
  assert.equal((await S('/api/site/incident', { op: 'add', k: 'nope', county: 'Kilifi', date: today, en: 'A long enough description' })).status, 400);
  const lr = await S('/api/site/incidents', null, 'GET'); const ls = lr.json; assert.equal(ls.rows.length, 2); assert.equal(ls.counties.length, 47);
  assert.equal((await S('/api/site/incident', { op: 'remove', k: 'crimes', sig: ls.rows[0].sig })).status, 200);
  assert.equal(JSON.parse(env.db.prepare("SELECT v FROM overlay WHERE k='crimes'").get().v).length, 1);
  assert.equal((await S('/api/site/incident', { op: 'add', k: 'reports', county: 'Mandera', date: today, en: 'Reported road closure near town' })).status, 200);
  assert.ok(env.db.prepare("SELECT 1 FROM site_audit WHERE act LIKE 'incident:%'").get());  env.db.exec('CREATE TABLE IF NOT EXISTS log (id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, note TEXT)');
  const r1 = await S('/api/site/refresh', {}); assert.equal(r1.status, 200); assert.ok(!r1.json.already);
  const r2 = await S('/api/site/refresh', {}); assert.equal(r2.json.already, true, 'one request per hour');
  assert.equal(env.db.prepare("SELECT count(*) n FROM log WHERE note LIKE 'REQUEST:%'").get().n, 1);
});

test('access requests: a second admin cannot decide, approve mints a real code, decline leaves none', async () => {
  const env = mkenv(); const S = call(env, token());
  env.db.exec("CREATE TABLE access_requests (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, org TEXT, email TEXT NOT NULL, role TEXT, use_case TEXT, at TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'new', ip TEXT, decided TEXT, plan TEXT NOT NULL DEFAULT 'free')");
  env.db.prepare("INSERT INTO access_requests (name,org,email,role,use_case,at) VALUES ('Ernest Ziro','Lola Studios','lola@example.com','Analyst or researcher','Public advocacy','2026-11-16T08:47:01Z')").run();
  env.db.prepare("INSERT INTO access_requests (name,org,email,role,use_case,at) VALUES ('Zuma','nkt','z@example.com','Government','media purposes','2026-11-06T20:19:28Z')").run();

  const list = await S('/api/site/access', null, 'GET');
  assert.equal(list.status, 200); assert.equal(list.json.pending.length, 2);

  await S('/api/site/roles', { editors: [{ email: 'ed@x.com', scopes: ['feedback'], approval: false }] });
  const E = call(env, token({ email: 'ed@x.com' }));
  assert.equal((await E('/api/site/access', null, 'GET')).status, 403, 'a non-super admin cannot see requests');
  assert.equal((await E('/api/site/access_decide', { id: 1, action: 'approve' })).status, 403, 'and cannot decide them');

  const bad = await S('/api/site/access_decide', { id: 999, action: 'approve' }); assert.equal(bad.status, 404);
  const badTerm = await S('/api/site/access_decide', { id: 1, action: 'approve', term: 'forever' }); assert.equal(badTerm.status, 400);

  const approve = await S('/api/site/access_decide', { id: 1, action: 'approve', role: 'full', term: 'paid31' });
  assert.equal(approve.status, 200);
  assert.match(approve.json.code, /^HAPA-[A-Z2-9]{4}-[A-Z2-9]{4}$/, 'a real, randomly generated code');
  const row = env.db.prepare('SELECT * FROM access_requests WHERE id=1').get();
  assert.equal(row.status, 'approved'); assert.ok(row.decided);
  const codeRow = env.db.prepare("SELECT * FROM codes WHERE agency='Lola Studios'").get();
  assert.ok(codeRow, 'the code was actually written to the codes table'); assert.equal(codeRow.email, 'lola@example.com'); assert.equal(codeRow.plan, 'paid'); assert.ok(codeRow.expires);
  assert.notEqual(codeRow.h, approve.json.code, 'only the hash is stored, never the plaintext code');
  assert.equal((await S('/api/site/access_decide', { id: 1, action: 'approve' })).status, 404, 'an already-decided request cannot be approved again');

  const decline = await S('/api/site/access_decide', { id: 2, action: 'decline' });
  assert.equal(decline.status, 200); assert.equal(decline.json.code, undefined, 'declining never mints a code');
  assert.equal(env.db.prepare('SELECT status FROM access_requests WHERE id=2').get().status, 'declined');
  assert.equal(env.db.prepare("SELECT count(*) n FROM codes WHERE agency='nkt'").get().n, 0);

  const after = await S('/api/site/access', null, 'GET');
  assert.equal(after.json.pending.length, 0); assert.equal(after.json.recent.length, 2); assert.equal(after.json.codes.length, 1);
  assert.ok(env.db.prepare("SELECT 1 FROM site_audit WHERE act='access approved'").get());
  assert.ok(env.db.prepare("SELECT 1 FROM site_audit WHERE act='access declined'").get());
});

test('public sign-ups: read-only, super-admin only, and degrades gracefully if the table is missing', async () => {
  const env = mkenv();
  const S = call(env, token({ super: true }));
  await S('/api/site/roles', { editors: [{ email: 'ed@x.com', scopes: ['notice', 'alert', 'home', 'contacts', 'articles', 'corrections', 'incidents'] }] });
  const E = call(env, token({ email: 'ed@x.com' }));

  // no users table at all yet -- hapa-public owns this table, so a schema hiccup there must never break Admin
  const missing = await S('/api/site/users', null, 'GET');
  assert.equal(missing.status, 200); assert.equal(missing.json.ok, true);
  assert.deepEqual(missing.json.rows, []); assert.equal(missing.json.total, 0);

  env.db.exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT, password TEXT, created TEXT, last_login TEXT, verified INTEGER, disabled INTEGER, google_sub TEXT)`);
  env.db.exec(`INSERT INTO users (name, email, password, created, last_login, verified, disabled, google_sub) VALUES
    ('Asha Wanjiru', 'asha@example.com', 'hash', '2026-01-02T10:00:00Z', '2026-11-20T08:00:00Z', 1, 0, NULL),
    (NULL, 'kip@example.com', '', '2026-03-01T10:00:00Z', NULL, 0, 0, NULL),
    ('Brian Otieno', 'brian@gmail.com', '', '2026-05-05T10:00:00Z', '2026-11-01T08:00:00Z', 1, 0, 'sub-123'),
    ('Old Account', 'gone@example.com', 'hash', '2026-02-02T10:00:00Z', NULL, 0, 1, NULL)`);

  const r = await S('/api/site/users', null, 'GET');
  assert.equal(r.status, 200); assert.equal(r.json.ok, true);
  assert.equal(r.json.total, 4); assert.equal(r.json.rows.length, 4);
  assert.equal(r.json.rows.every((u) => !('password' in u)), true, 'password hash is never returned, even to a super-admin');
  const brian = r.json.rows.find((u) => u.email === 'brian@gmail.com');
  assert.equal(brian.google, 1, 'google sign-in is flagged');
  const asha = r.json.rows.find((u) => u.email === 'asha@example.com');
  assert.equal(asha.google, 0);

  // a non-super admin, even one with other scopes, cannot see this
  assert.equal((await E('/api/site/users', null, 'GET')).status, 403, 'public sign-ups are super-admin only, not a per-area scope');
});
