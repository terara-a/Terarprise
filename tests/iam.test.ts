import { beforeAll, afterAll, beforeEach, expect, test, vi } from 'vitest';
import { getPlatformProxy } from 'wrangler';
import { readFileSync } from 'node:fs';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import worker, { hash, type Env } from '../src/index';
let env: Env, dispose: () => Promise<void>;
const origin = 'http://localhost:8787';
const request = (path: string, init?: RequestInit) => worker.fetch(new Request(origin + path, init), env);
const session = (token: string) => ({headers:{Cookie:`session=${token}`}});
beforeAll(async () => {
  const platform = await getPlatformProxy<Env>({persist:false});
  dispose = platform.dispose; env = {...platform.env, APP_ORIGIN:origin};
  for (const sql of readFileSync('migrations/0001_iam.sql','utf8').replace(/--[^\n]*/g, '').split(';').filter(s => s.trim())) await env.DB.prepare(sql).run();
  await env.DB.exec("INSERT INTO organizations VALUES ('acme','Acme'),('globex','Globex'); INSERT INTO users VALUES ('u1','https://idp.example','alice'),('u2','https://idp.example','bob'); INSERT INTO memberships VALUES ('acme','u1','admin',1),('acme','u2','member',1); INSERT INTO oidc_providers VALUES ('acme','https://idp.example','client');");
},30000);
afterAll(async () => { vi.unstubAllGlobals(); await dispose?.(); });
beforeEach(async () => {
  vi.unstubAllGlobals();
  await env.DB.exec('DELETE FROM sessions; DELETE FROM login_transactions; UPDATE memberships SET active=1;');
  for (const [token,user] of [['admin','u1'],['member','u2']]) await env.DB.prepare('INSERT INTO sessions VALUES (?, ?, ?, ?)').bind(await hash(token),'acme',user,Math.floor(Date.now()/1000)+3600).run();
});
test('health exercises migrated D1',async () => expect(await (await request('/health')).json()).toEqual({status:'ok'}));
test('anonymous denied',async () => expect((await request('/api/organizations/acme/me')).status).toBe(401));
test('organization isolation and RBAC',async () => {
  expect((await request('/api/organizations/globex/me',session('admin'))).status).toBe(403);
  expect((await request('/api/organizations/acme/me',session('member'))).status).toBe(200);
  expect((await request('/api/organizations/acme/admin',session('member'))).status).toBe(403);
  expect((await request('/api/organizations/acme/admin',session('admin'))).status).toBe(200);
  const events = await (await request('/api/organizations/acme/audit',session('admin'))).json() as any[];
  expect(events.some(e => e.action === 'admin.access')).toBe(true);
});
test('disable, role change and expiry apply to existing sessions',async () => {
  await env.DB.exec("UPDATE memberships SET active=0 WHERE user_id='u2';");
  expect((await request('/api/organizations/acme/me',session('member'))).status).toBe(401);
  await env.DB.exec("UPDATE memberships SET role='member' WHERE user_id='u1';");
  expect((await request('/api/organizations/acme/admin',session('admin'))).status).toBe(403);
  await env.DB.exec("UPDATE sessions SET expires_at=0;");
  expect((await request('/api/organizations/acme/me',session('admin'))).status).toBe(401);
  await env.DB.exec("UPDATE memberships SET role='admin' WHERE user_id='u1';");
});
test('logout checks origin and invalidates session',async () => {
  expect((await request('/auth/logout',{method:'POST',headers:{Cookie:'session=admin',Origin:'https://evil.example'}})).status).toBe(403);
  expect((await request('/auth/logout',{method:'POST',headers:{Cookie:'session=admin',Origin:origin}})).status).toBe(204);
  expect((await request('/api/organizations/acme/me',session('admin'))).status).toBe(401);
});
test('OIDC code flow validates signed token, PKCE, nonce and single-use state',async () => {
  const {privateKey,publicKey} = await generateKeyPair('RS256');
  const jwk = {...await exportJWK(publicKey),kid:'test',alg:'RS256',use:'sig'};
  let nonce = '', verifier = '', audience = 'client', subject = 'alice';
  vi.stubGlobal('fetch',vi.fn(async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith('openid-configuration')) return Response.json({issuer:'https://idp.example',authorization_endpoint:'https://idp.example/authorize',token_endpoint:'https://idp.example/token',jwks_uri:'https://idp.example/jwks'});
    if (url.endsWith('/jwks')) return Response.json({keys:[jwk]});
    if (url.endsWith('/token')) {
      verifier = new URLSearchParams(String(init?.body)).get('code_verifier')!;
      return Response.json({id_token:await new SignJWT({nonce}).setProtectedHeader({alg:'RS256',kid:'test'}).setIssuer('https://idp.example').setAudience(audience).setSubject(subject).setIssuedAt().setExpirationTime('5m').sign(privateKey)});
    }
    throw new Error('Unexpected upstream');
  }));
  const login = await request('/auth/login?organization=acme'); expect(login.status).toBe(302);
  const auth = new URL(login.headers.get('Location')!); nonce = auth.searchParams.get('nonce')!;
  expect(auth.searchParams.get('code_challenge_method')).toBe('S256');
  const path = '/auth/callback?code=test&state='+auth.searchParams.get('state');
  expect((await request(path)).status).toBe(400);
  const headers = {Cookie:login.headers.get('Set-Cookie')!.split(';')[0]};
  const callback = await request(path,{headers}); expect(callback.status).toBe(302);
  const challenge = Buffer.from(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(verifier))).toString('base64url');
  expect(challenge).toBe(auth.searchParams.get('code_challenge'));
  const stored = await env.DB.prepare('SELECT count(*) AS n FROM sessions').first<{n:number}>(); expect(stored?.n).toBe(3);
  expect((await request(path,{headers})).status).toBe(400);
  for (const invalid of ['nonce','audience','membership']) {
    const next = await request('/auth/login?organization=acme');
    const target = new URL(next.headers.get('Location')!);
    nonce = invalid === 'nonce' ? 'wrong-nonce' : target.searchParams.get('nonce')!;
    audience = invalid === 'audience' ? 'other-client' : 'client';
    subject = invalid === 'membership' ? 'unknown-user' : 'alice';
    const rejected = await request('/auth/callback?code=test&state='+target.searchParams.get('state'),{headers:{Cookie:next.headers.get('Set-Cookie')!.split(';')[0]}});
    expect(rejected.status).toBe(invalid === 'nonce' ? 400 : invalid === 'membership' ? 403 : 500);
    expect((await env.DB.prepare('SELECT count(*) AS n FROM sessions').first<{n:number}>())?.n).toBe(3);
  }
});
