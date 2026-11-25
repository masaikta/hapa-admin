// Hapa Admin: settings for the public site, on its own subdomain (admin.homesupport.co.ke), separate from Hapa Pro.
// Two locks: Cloudflare Access in front, and this worker verifies the Access token itself and accepts only the super administrator.
// Until ACCESS_TEAM and ACCESS_AUD are set it refuses everything, so a half-finished setup is never open.
import { siteApi, ensureSite, SCOPES, cron } from './site.js';

const SUPER_DEFAULT = ['masaikta@gmail.com'];
export const isSuper = (env, email) => { const e = String(email || '').trim().toLowerCase(); return !!e && String(env.SUPER_ADMINS || SUPER_DEFAULT.join(',')).toLowerCase().split(',').map((x) => x.trim()).includes(e); };
const J = (obj, status = 200) => new Response(JSON.stringify(obj), { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
const b64 = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(s.length / 4) * 4, '=')), (c) => c.charCodeAt(0));

let KEYS = { at: 0, keys: null };
async function certs(env) {
  if (KEYS.keys && Date.now() - KEYS.at < 3600e3) return KEYS.keys;
  const r = await fetch('https://' + env.ACCESS_TEAM + '.cloudflareaccess.com/cdn-cgi/access/certs');
  if (!r.ok) throw new Error('certs');
  KEYS = { at: Date.now(), keys: (await r.json()).keys || [] }; return KEYS.keys;
}
// Returns the verified email, or '' when the token is missing, forged, for another application or expired.
export async function accessEmail(request, env) {
  const t = request.headers.get('cf-access-jwt-assertion') || '';
  const p = t.split('.'); if (p.length !== 3) return '';
  try {
    const head = JSON.parse(new TextDecoder().decode(b64(p[0]))), body = JSON.parse(new TextDecoder().decode(b64(p[1])));
    if (head.alg !== 'RS256') return '';
    const jwk = (await certs(env)).find((k) => k.kid === head.kid); if (!jwk) return '';
    const key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
    if (!(await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, b64(p[2]), new TextEncoder().encode(p[0] + '.' + p[1])))) return '';
    const aud = Array.isArray(body.aud) ? body.aud : [body.aud];
    if (!aud.includes(env.ACCESS_AUD) || body.iss !== 'https://' + env.ACCESS_TEAM + '.cloudflareaccess.com' || !(body.exp > Date.now() / 1000)) return '';
    return String(body.email || '').toLowerCase();
  } catch (e) { return ''; }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (!env.ACCESS_TEAM || !env.ACCESS_AUD) return new Response('Hapa Admin is not switched on yet: the Cloudflare Access settings are missing.', { status: 503, headers: { 'cache-control': 'no-store' } });
    const email = await accessEmail(request, env);
    if (!email) return new Response('Sign in through Cloudflare Access.', { status: 403, headers: { 'cache-control': 'no-store' } });
    // The super administrator has everything; a second admin named under Roles gets only the areas ticked for them.
    let who = { email, super: isSuper(env, email), scopes: [] };
    if (!who.super) {
      try { await ensureSite(env); const r = await env.DB.prepare("SELECT v FROM site_settings WHERE k='roles'").first(); const ed = ((r && JSON.parse(r.v)) || {}).editors || []; const me = ed.find((x) => x.email === email); if (me) { who.scopes = (me.scopes || []).filter((x) => SCOPES.includes(x)); who.approval = !!me.approval; who.readonly = !!me.readonly; } } catch (e) { /* no roles yet */ }
      if (!who.scopes.length) return new Response('Not found', { status: 404, headers: { 'cache-control': 'no-store' } });
    }
    if (url.pathname.startsWith('/api/')) {
      const act = url.pathname.slice(5); // /api/site/<action>
      if (request.method === 'POST') {
        const o = request.headers.get('origin'); if (o && o !== url.origin) return J({ ok: false, error: 'origin' }, 403);
        if (!/application\/json/.test(request.headers.get('content-type') || '')) return J({ ok: false, error: 'type' }, 415);
      } else if (request.method !== 'GET') return J({ ok: false, error: 'method' }, 405);
      let body = request.method === 'GET' ? Object.fromEntries(url.searchParams) : null; if (request.method === 'POST') { if (Number(request.headers.get('content-length') || 0) > 100000) return J({ ok: false, error: 'big' }, 413); try { body = (await request.json()) || {}; } catch (e) { body = {}; } }
      try { const [st, js] = await siteApi(env, who, act, request.method, body); return J(js, st); } catch (e) { return J({ ok: false, error: 'db' }, 502); }
    }
    const r = await env.ASSETS.fetch(request); const h = new Headers(r.headers);
    h.set('cache-control', 'no-store'); h.set('x-content-type-options', 'nosniff'); h.set('referrer-policy', 'no-referrer'); h.set('content-security-policy', "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline' 'self'; img-src 'self' data: blob: https://homesupport.co.ke; frame-ancestors 'none'");
    return new Response(r.body, { status: r.status, headers: h });
  },
  // Cron: publishes or takes down scheduled articles and re-checks article links about weekly.
  async scheduled(event, env, ctx) { ctx.waitUntil(cron(env)); },
};
