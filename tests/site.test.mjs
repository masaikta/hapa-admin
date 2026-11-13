import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import worker from '../src/worker.js';
import { cleanContact, cleanNums } from '../src/site.js';

function fakeD1() {
  const db = new DatabaseSync(':memory:');
  db.exec("CREATE TABLE ops_events (id INTEGER PRIMARY KEY AUTOINCREMENT, agency TEXT, category TEXT, date TEXT, county TEXT, subcounty TEXT, place TEXT, arrests INT, fines INT, quantity REAL, unit TEXT, note TEXT, created TEXT, code_id INT, src TEXT)");
  db.exec("CREATE TABLE codes (id INTEGER PRIMARY KEY, h TEXT, label TEXT, agency TEXT, plan TEXT, expires TEXT, revoked INT DEFAULT 0, created TEXT, last_used TEXT, uses INT DEFAULT 0, role TEXT DEFAULT 'full', ack TEXT); CREATE TABLE sessions (th TEXT, code_id INT, at TEXT); CREATE TABLE attempts (ip TEXT, at TEXT)");
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
  assert.deepEqual((await S('/api/site/get', null, 'GET')).json.settings.roles.editors, [{ email: 'ed@x.com', scopes: ['notice'] }]);
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
