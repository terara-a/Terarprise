const origin = process.env.TEST_ORIGIN ?? 'http://localhost:8787';
for (const [path,status] of [['/',200],['/health',200],['/api/organizations/acme/me',401],['/auth/callback?state=invalid',400]]) {
  const response = await fetch(origin+path);
  if (response.status !== status) throw new Error(`${path}: ${response.status}, expected ${status}`);
  if (path === '/health' && (await response.json()).status !== 'ok') throw new Error('D1 health failed');
  console.log(`PASS ${path} (${status})`);
}
