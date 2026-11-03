import { createRemoteJWKSet, jwtVerify } from 'jose';

export interface Env { DB: D1Database; APP_ORIGIN: string; OIDC_CLIENT_SECRETS?: string }
type Provider = { organization_id: string; issuer: string; client_id: string };
type Identity = { user_id: string; organization_id: string; role: 'admin' | 'member' };
const now = () => Math.floor(Date.now() / 1000);
export const random = () => Array.from(crypto.getRandomValues(new Uint8Array(32)), b => b.toString(16).padStart(2, '0')).join('');
export async function hash(value: string) {
  return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))), b => b.toString(16).padStart(2, '0')).join('');
}
function cookieName(env: Env, name: string) { return new URL(env.APP_ORIGIN).protocol === 'https:' ? `__Host-${name}` : name; }
function cookie(req: Request, env: Env, name: string) {
  return req.headers.get('Cookie')?.split(';').map(s => s.trim()).find(s => s.startsWith(`${cookieName(env, name)}=`))?.split('=')[1];
}
function setCookie(env: Env, name: string, value: string, age: number) {
  return `${cookieName(env, name)}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${age}${new URL(env.APP_ORIGIN).protocol === 'https:' ? '; Secure' : ''}`;
}
function json(body: unknown, status = 200) { return Response.json(body, { status }); }
function fail(status: number, message: string): never { throw new Response(JSON.stringify({ error: message }), { status, headers: { 'Content-Type': 'application/json' } }); }
function https(value: string) { const url = new URL(value); if (url.protocol !== 'https:' || url.username || url.password || url.hash) fail(502, 'Invalid OIDC endpoint'); return url; }
async function metadata(provider: Provider) {
  const issuer = https(provider.issuer);
  const response = await fetch(`${issuer.href.replace(/\/$/, '')}/.well-known/openid-configuration`, { redirect: 'error', signal: AbortSignal.timeout(10000) });
  if (!response.ok) fail(502, 'OIDC discovery failed');
  const data = await response.json() as { issuer: string; authorization_endpoint: string; token_endpoint: string; jwks_uri: string; token_endpoint_auth_methods_supported?: string[] };
  if (data.issuer !== provider.issuer) fail(502, 'Issuer mismatch');
  https(data.authorization_endpoint); https(data.token_endpoint); https(data.jwks_uri);
  return data;
}
async function provider(env: Env, org: string) {
  const result = await env.DB.prepare('SELECT * FROM oidc_providers WHERE organization_id = ?').bind(org).first<Provider>();
  if (!result) fail(404, 'SSO is not configured for this organization');
  return result;
}
async function audit(env: Env, identity: Identity, action: string) {
  await env.DB.prepare('INSERT INTO audit_events VALUES (?, ?, ?, ?, ?)').bind(random(), identity.organization_id, identity.user_id, action, now()).run();
}
type AuditEvent = { id: string; user_id: string | null; action: string; created_at: number };
async function auditPage(env: Env, org: string, url: URL): Promise<Response> {
  const rawLimit = url.searchParams.get('limit') ?? '100';
  if (!/^[1-9]\d{0,2}$/.test(rawLimit) || Number(rawLimit) > 100) fail(400, 'Limit must be an integer between 1 and 100');
  const limit = Number(rawLimit);
  let cursor: { organization_id: string; created_at: number; id: string } | undefined;
  if (url.searchParams.has('cursor')) {
    try {
      const value = url.searchParams.get('cursor')!;
      if (value.length > 1024 || !/^[A-Za-z0-9_-]+$/.test(value)) throw new Error();
      cursor = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), char => char.charCodeAt(0))));
      if (!cursor || cursor.organization_id !== org || !Number.isSafeInteger(cursor.created_at) || cursor.created_at < 0 || !/^[a-f0-9]{64}$/.test(cursor.id)) throw new Error();
    } catch { fail(400, 'Invalid audit cursor'); }
  }
  const query = cursor
    ? env.DB.prepare('SELECT id, user_id, action, created_at FROM audit_events WHERE organization_id = ? AND (created_at, id) < (?, ?) ORDER BY created_at DESC, id DESC LIMIT ?').bind(org, cursor.created_at, cursor.id, limit + 1)
    : env.DB.prepare('SELECT id, user_id, action, created_at FROM audit_events WHERE organization_id = ? ORDER BY created_at DESC, id DESC LIMIT ?').bind(org, limit + 1);
  const events = (await query.all<AuditEvent>()).results;
  const response = json(events.slice(0, limit));
  if (events.length > limit) {
    const last = events[limit - 1];
    const next = new URL(url.pathname, url.origin);
    next.searchParams.set('limit', String(limit));
    const value = new TextEncoder().encode(JSON.stringify({ organization_id: org, created_at: last.created_at, id: last.id }));
    next.searchParams.set('cursor', btoa(String.fromCharCode(...value)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''));
    response.headers.set('Link', `<${next.pathname}${next.search}>; rel="next"`);
  }
  return response;
}
export async function authorize(req: Request, env: Env, org: string, admin = false): Promise<Identity> {
  const token = cookie(req, env, 'session');
  if (!token) fail(401, 'Sign in required');
  const identity = await env.DB.prepare(`SELECT s.user_id, s.organization_id, m.role FROM sessions s JOIN memberships m
    ON s.organization_id = m.organization_id AND s.user_id = m.user_id
    WHERE s.token_hash = ? AND s.expires_at > ? AND m.active = 1`).bind(await hash(token), now()).first<Identity>();
  if (!identity) fail(401, 'Session expired or membership disabled');
  if (identity.organization_id !== org) fail(403, 'Organization access denied');
  if (admin && identity.role !== 'admin') fail(403, 'Administrator role required');
  return identity;
}
async function route(req: Request, env: Env): Promise<Response> {
  const url = new URL(req.url);
  if (req.method === 'GET' && url.pathname === '/health') {
    await env.DB.prepare('SELECT id FROM organizations LIMIT 1').all();
    return json({ status: 'ok' });
  }
  if (req.method === 'GET' && url.pathname === '/') {
    return new Response(`<!doctype html><html lang="ja"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Terarprise</title><style>body{font:18px system-ui;max-width:720px;margin:80px auto;padding:24px;color:#17243b}input,button{font:inherit;padding:12px;margin:8px 0}label{display:block}button{background:#2457d6;color:white;border:0;border-radius:6px}</style><h1>Terarprise</h1><p>企業のアカウントでサインインします。</p><form action="/auth/login" method="get"><label>組織 ID <input name="organization" required pattern="[a-zA-Z0-9_-]+" placeholder="acme"></label><button>SSO でサインイン</button></form></html>`, { headers: { 'Content-Type': 'text/html; charset=utf-8', 'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'" } });
  }
  if (req.method === 'GET' && url.pathname === '/auth/login') {
    const org = url.searchParams.get('organization') ?? '';
    const p = await provider(env, org); const discovery = await metadata(p);
    const state = random(), verifier = random(), nonce = random();
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)));
    const challenge = btoa(String.fromCharCode(...digest)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    await env.DB.batch([
      env.DB.prepare('DELETE FROM login_transactions WHERE expires_at <= ?').bind(now()),
      env.DB.prepare('INSERT INTO login_transactions VALUES (?, ?, ?, ?, ?)').bind(await hash(state), org, verifier, nonce, now() + 600),
    ]);
    const target = new URL(discovery.authorization_endpoint);
    Object.entries({ client_id: p.client_id, response_type: 'code', scope: 'openid profile', redirect_uri: `${env.APP_ORIGIN}/auth/callback`, state, nonce, code_challenge: challenge, code_challenge_method: 'S256' }).forEach(([k,v]) => target.searchParams.set(k,v));
    return new Response(null, { status: 302, headers: { Location: target.href, 'Set-Cookie': setCookie(env, 'oidc_state', state, 600) } });
  }
  if (req.method === 'GET' && url.pathname === '/auth/callback') {
    const state = url.searchParams.get('state');
    if (!state || cookie(req, env, 'oidc_state') !== state) fail(400, 'Invalid login state');
    const tx = await env.DB.prepare('DELETE FROM login_transactions WHERE state_hash = ? AND expires_at > ? RETURNING *').bind(await hash(state), now()).first<{organization_id:string; verifier:string; nonce:string}>();
    if (!tx) fail(400, 'Login expired or already used');
    const code = url.searchParams.get('code'); if (!code) fail(400, 'Authorization code missing');
    const p = await provider(env, tx.organization_id); const discovery = await metadata(p);
    const secrets = JSON.parse(env.OIDC_CLIENT_SECRETS ?? '{}') as Record<string,string>;
    const secret = secrets[p.organization_id];
    const body = new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: `${env.APP_ORIGIN}/auth/callback`, code_verifier: tx.verifier });
    const headers: Record<string,string> = { 'Content-Type': 'application/x-www-form-urlencoded' };
    if (secret) {
      const methods = discovery.token_endpoint_auth_methods_supported ?? ['client_secret_basic'];
      if (methods.includes('client_secret_basic')) {
        const encode = (v: string) => new URLSearchParams({v}).toString().slice(2);
        headers.Authorization = `Basic ${btoa(`${encode(p.client_id)}:${encode(secret)}`)}`;
      } else if (methods.includes('client_secret_post')) { body.set('client_id', p.client_id); body.set('client_secret', secret); }
      else fail(502, 'Unsupported client authentication method');
    } else body.set('client_id', p.client_id);
    const response = await fetch(discovery.token_endpoint, { method:'POST', headers, body, redirect:'error', signal:AbortSignal.timeout(10000) });
    if (!response.ok) fail(502, 'Token exchange failed');
    const tokens = await response.json() as { id_token?: string };
    if (!tokens.id_token) fail(502, 'ID token missing');
    const { payload } = await jwtVerify(tokens.id_token, createRemoteJWKSet(new URL(discovery.jwks_uri)), { issuer:p.issuer, audience:p.client_id, algorithms:['RS256','ES256'], requiredClaims:['exp','iat','sub','nonce'], maxTokenAge:'10m' });
    if (payload.nonce !== tx.nonce || !payload.sub || (payload.azp !== undefined && payload.azp !== p.client_id) || (Array.isArray(payload.aud) && payload.aud.length > 1 && payload.azp !== p.client_id)) fail(400, 'Invalid ID token');
    const identity = await env.DB.prepare(`SELECT m.user_id, m.organization_id, m.role FROM memberships m JOIN users u ON m.user_id = u.id
      WHERE u.issuer = ? AND u.subject = ? AND m.organization_id = ? AND m.active = 1`).bind(p.issuer, payload.sub, p.organization_id).first<Identity>();
    if (!identity) fail(403, 'Membership must be provisioned by an administrator');
    const token = random();
    await env.DB.batch([
      env.DB.prepare('DELETE FROM sessions WHERE expires_at <= ?').bind(now()),
      env.DB.prepare('INSERT INTO sessions VALUES (?, ?, ?, ?)').bind(await hash(token), p.organization_id, identity.user_id, now()+28800),
      env.DB.prepare('INSERT INTO audit_events VALUES (?, ?, ?, ?, ?)').bind(random(), identity.organization_id, identity.user_id, 'login', now()),
    ]);
    const result = new Response(null, { status:302, headers: { Location:`${env.APP_ORIGIN}/api/organizations/${encodeURIComponent(p.organization_id)}/me` } });
    result.headers.append('Set-Cookie', setCookie(env, 'session', token, 28800));
    result.headers.append('Set-Cookie', setCookie(env, 'oidc_state', '', 0)); return result;
  }
  if (req.method === 'POST' && url.pathname === '/auth/logout') {
    if (req.headers.get('Origin') !== env.APP_ORIGIN) fail(403, 'Invalid request origin');
    const token = cookie(req, env, 'session');
    if (token) {
      const tokenHash = await hash(token);
      await env.DB.batch([
        env.DB.prepare(`INSERT INTO audit_events (id, organization_id, user_id, action, created_at)
          SELECT ?, organization_id, user_id, 'logout', ? FROM sessions WHERE token_hash = ? AND expires_at > ?`).bind(random(), now(), tokenHash, now()),
        env.DB.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(tokenHash),
      ]);
    }
    return new Response(null, {status:204, headers:{'Set-Cookie':setCookie(env,'session','',0)}});
  }
  const match = /^\/api\/organizations\/([^/]+)\/(me|admin|audit)$/.exec(url.pathname);
  if (req.method === 'GET' && match) {
    const identity = await authorize(req, env, decodeURIComponent(match[1]), match[2] !== 'me');
    if (match[2] === 'audit') return auditPage(env, identity.organization_id, url);
    if (match[2] === 'admin') { await audit(env, identity, 'admin.access'); return json({message:'Administrator access granted', ...identity}); }
    return json(identity);
  }
  return json({error:'Not found'},404);
}
export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    let response: Response;
    try { response = await route(req,env); }
    catch (error) {
      if (error instanceof Response) response = error;
      else { console.error('Request failed', error instanceof Error ? error.name : 'UnknownError'); response = json({error:'Request could not be completed'},500); }
    }
    response.headers.set('Cache-Control','no-store'); response.headers.set('X-Content-Type-Options','nosniff'); response.headers.set('Referrer-Policy','no-referrer');
    return response;
  }
};
