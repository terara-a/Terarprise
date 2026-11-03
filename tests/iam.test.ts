import { beforeAll, afterAll, beforeEach, expect, test, vi } from 'vitest';
import { getPlatformProxy } from 'wrangler';
import { readFileSync, readdirSync } from 'node:fs';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import worker, { hash, type Env } from '../src/index';
let env: Env, dispose: () => Promise<void>;
const origin = 'http://localhost:8787';
const request = (path: string, init?: RequestInit) => worker.fetch(new Request(origin + path, init), env);
const session = (token: string) => ({headers:{Cookie:`session=${token}`}});
beforeAll(async () => {
  const platform = await getPlatformProxy<Env>({persist:false});
  dispose = platform.dispose; env = {...platform.env, APP_ORIGIN:origin};
  for (const file of readdirSync('migrations').filter(file => file.endsWith('.sql')).sort()) {
    for (const sql of readFileSync(`migrations/${file}`,'utf8').replace(/--[^\n]*/g, '').split(';').filter(s => s.trim())) await env.DB.prepare(sql).run();
  }
  await env.DB.exec("INSERT INTO organizations VALUES ('acme','Acme'),('globex','Globex'); INSERT INTO users VALUES ('u1','https://idp.example','alice'),('u2','https://idp.example','bob'); INSERT INTO memberships VALUES ('acme','u1','admin',1),('acme','u2','member',1); INSERT INTO oidc_providers VALUES ('acme','https://idp.example','client');");
},30000);
afterAll(async () => { vi.unstubAllGlobals(); await dispose?.(); });
beforeEach(async () => {
  vi.unstubAllGlobals();
  await env.DB.exec("DELETE FROM sessions; DELETE FROM login_transactions; DELETE FROM audit_events; UPDATE memberships SET active=1; UPDATE memberships SET role='admin' WHERE user_id='u1';");
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
  expect((await env.DB.prepare('SELECT count(*) AS n FROM audit_events').first<{n:number}>())?.n).toBe(0);
  expect((await request('/auth/logout',{method:'POST',headers:{Cookie:'session=admin',Origin:origin}})).status).toBe(204);
  expect((await request('/api/organizations/acme/me',session('admin'))).status).toBe(401);
  expect((await request('/auth/logout',{method:'POST',headers:{Cookie:'session=admin',Origin:origin}})).status).toBe(204);
  expect((await env.DB.prepare('SELECT organization_id, user_id, action FROM audit_events').all()).results).toEqual([{organization_id:'acme',user_id:'u1',action:'logout'}]);
});
test('audit pages handle timestamp ties, new events and organization boundaries',async () => {
  const id = (n: number) => n.toString(16).padStart(64, '0');
  for (let n = 1; n <= 5; n++) await env.DB.prepare('INSERT INTO audit_events VALUES (?, ?, ?, ?, ?)').bind(id(n),'acme','u1','admin.access',n === 1 ? 9 : 10).run();
  await env.DB.prepare('INSERT INTO audit_events VALUES (?, ?, ?, ?, ?)').bind(id(6),'globex',null,'login',10).run();
  const first = await request('/api/organizations/acme/audit?limit=2',session('admin'));
  expect(await first.json()).toEqual([5,4].map(n => ({id:id(n),user_id:'u1',action:'admin.access',created_at:10})));
  const nextPath = (response: Response) => response.headers.get('Link')!.match(/^<([^>]+)>; rel="next"$/)![1];
  const next = nextPath(first);
  // Inserts newer than the cursor must not duplicate or displace the remaining page.
  await env.DB.prepare('INSERT INTO audit_events VALUES (?, ?, ?, ?, ?)').bind(id(7),'acme','u1','login',11).run();
  const second = await request(next,session('admin'));
  expect((await second.json() as {id:string}[]).map(e => e.id)).toEqual([id(3),id(2)]);
  const last = await request(nextPath(second),session('admin'));
  expect((await last.json() as {id:string}[]).map(e => e.id)).toEqual([id(1)]);
  expect(last.headers.has('Link')).toBe(false);
  expect((await request(next)).status).toBe(401);
  expect((await request(next,session('member'))).status).toBe(403);
  await env.DB.prepare('INSERT INTO memberships VALUES (?, ?, ?, ?)').bind('globex','u1','admin',1).run();
  await env.DB.prepare('INSERT INTO sessions VALUES (?, ?, ?, ?)').bind(await hash('globex-admin'),'globex','u1',Math.floor(Date.now()/1000)+3600).run();
  expect((await request(next.replace('/acme/','/globex/'),session('globex-admin'))).status).toBe(400);
});
test('audit validates pagination input and keeps the default array response',async () => {
  for (const query of ['limit=0','limit=101','limit=-1','limit=1.5','limit=','limit=1e2','cursor=','cursor=bad','cursor='+btoa('null'),'cursor='+btoa('{"created_at":1}')]) {
    expect((await request('/api/organizations/acme/audit?'+query,session('admin'))).status).toBe(400);
  }
  const response = await request('/api/organizations/acme/audit',session('admin'));
  expect(await response.json()).toEqual([]);
  expect(response.headers.has('Link')).toBe(false);
});
test('expired and unknown logout sessions do not create audit events',async () => {
  await env.DB.exec('UPDATE sessions SET expires_at=0;');
  for (const token of ['admin','unknown']) expect((await request('/auth/logout',{method:'POST',headers:{Cookie:`session=${token}`,Origin:origin}})).status).toBe(204);
  expect((await env.DB.prepare('SELECT count(*) AS n FROM audit_events').first<{n:number}>())?.n).toBe(0);
});
test('audit defaults to 100 rows and supports non-ASCII organization cursors',async () => {
  const org = '組織';
  await env.DB.prepare('INSERT INTO organizations VALUES (?, ?)').bind(org,org).run();
  await env.DB.prepare('INSERT INTO memberships VALUES (?, ?, ?, ?)').bind(org,'u1','admin',1).run();
  await env.DB.prepare('INSERT INTO sessions VALUES (?, ?, ?, ?)').bind(await hash('unicode-admin'),org,'u1',Math.floor(Date.now()/1000)+3600).run();
  await env.DB.batch(Array.from({length:101}, (_, n) => env.DB.prepare('INSERT INTO audit_events VALUES (?, ?, ?, ?, ?)').bind(n.toString(16).padStart(64,'0'),org,'u1','login',10)));
  const first = await request('/api/organizations/'+encodeURIComponent(org)+'/audit',session('unicode-admin'));
  expect((await first.json() as unknown[]).length).toBe(100);
  const next = first.headers.get('Link')!.match(/^<([^>]+)>; rel="next"$/)![1];
  const last = await request(next,session('unicode-admin'));
  expect((await last.json() as {id:string}[]).map(e => e.id)).toEqual(['0'.repeat(64)]);
  expect(last.headers.has('Link')).toBe(false);
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
