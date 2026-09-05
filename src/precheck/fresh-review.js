import { createHash, timingSafeEqual, createPublicKey, verify } from 'node:crypto';
import { gunzipSync } from 'node:zlib';

const MAX_DOWNLOAD = 20 * 1024 * 1024;
const MAX_EXPANDED = 64 * 1024 * 1024;

export async function readBounded(response, limit) {
  if (!response.ok || !response.body) throw new Error('review download unavailable');
  const chunks = [];
  let size = 0;
  for await (const chunk of response.body) {
    size += chunk.length;
    if (size > limit) throw new Error('review size limit exceeded');
    chunks.push(Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}

/** Read regular files in memory. Never extract or execute package contents. */
export function inspectArchive(archive, pkg) {
  const tar = gunzipSync(archive, { maxOutputLength: MAX_EXPANDED });
  const findings = [];
  let manifest;
  let files = 0;
  let ended = false;
  const paths = new Set();
  for (let offset = 0; offset + 512 <= tar.length;) {
    const header = tar.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) {
      if (offset + 1024 > tar.length || !tar.subarray(offset).every((byte) => byte === 0)) throw new Error('invalid archive termination or trailing entries');
      ended = true;
      break;
    }
    const field = (start, length) => header.subarray(start, start + length).toString('utf8').replace(/\0.*$/s, '');
    const sizeText = field(124, 12).trim();
    if (!/^[0-7]+$/.test(sizeText)) throw new Error('unsupported archive size');
    const size = Number.parseInt(sizeText, 8);
    const checksum = Number.parseInt(field(148, 8).trim(), 8);
    const actual = header.reduce((sum, byte, index) => sum + (index >= 148 && index < 156 ? 32 : byte), 0);
    if (checksum !== actual) throw new Error('invalid archive checksum');
    const name = [field(345, 155), field(0, 100)].filter(Boolean).join('/');
    if (!name.startsWith('package/') || name.includes('\\') || name.includes('//') || /[\x00-\x1f\x7f]/.test(name) || name.split('/').includes('..')) throw new Error('unsafe archive path');
    if (name.split('/').includes('.') || paths.has(name)) throw new Error('duplicate or ambiguous archive path');
    paths.add(name);
    const type = field(156, 1);
    if (!['', '0', '5'].includes(type)) throw new Error('unsupported archive entry type');
    const end = offset + 512 + size;
    if (end > tar.length) throw new Error('truncated archive');
    if (++files > 10000) throw new Error('archive file limit exceeded');
    if (type !== '5') {
      const content = tar.subarray(offset + 512, end).toString('utf8');
      if (name === 'package/package.json') {
        if (manifest) throw new Error('duplicate package manifest');
        manifest = JSON.parse(content);
      }
      if (/\.(?:[cm]?js|json|sh|ps1|cmd|bat)$/i.test(name)) {
        if (/\b(?:curl|wget)\b[^\n]{0,300}\|\s*(?:sh|bash)|Invoke-Expression|\bIEX\s*\(/i.test(content)) findings.push(`download-and-execute pattern in ${name}`);
        if (/eval\s*\(\s*(?:atob|Buffer\.from)|child_process[^\n]{0,200}base64/i.test(content)) findings.push(`encoded execution pattern in ${name}`);
      }
    }
    offset += 512 + Math.ceil(size / 512) * 512;
  }
  if (!ended || !manifest || manifest.name !== pkg.name || manifest.version !== pkg.version) throw new Error('archive manifest or termination mismatch');
  const installScripts = ['preinstall', 'install', 'postinstall'].filter((name) => manifest.scripts?.[name]);
  if (paths.has('package/binding.gyp') && !manifest.scripts?.install && !manifest.scripts?.preinstall) {
    findings.push('binding.gyp triggers implicit native installation (node-gyp rebuild)');
  }
  return { files, findings, installScripts, lifecycleCommands: Object.fromEntries(installScripts.map((name) => [name, manifest.scripts[name]])) };
}

/** Evidence only: a clean static review cannot establish that a package is safe. */
export async function reviewFreshPackage(pkg, metadata, fetchImpl = fetch) {
  try {
    const url = new URL(metadata?.dist?.tarball);
    if (url.protocol !== 'https:' || url.hostname !== 'registry.npmjs.org' || url.username || url.password || url.port) throw new Error('untrusted archive URL');
    const integrity = metadata?.dist?.integrity;
    if (typeof integrity !== 'string' || !/^sha512-[A-Za-z0-9+/]+={0,2}$/.test(integrity)) throw new Error('SHA-512 integrity is required');
    const response = await fetchImpl(url.href, { redirect: 'error', signal: AbortSignal.timeout(20000) });
    const archive = await readBounded(response, MAX_DOWNLOAD);
    const digest = createHash('sha512').update(archive).digest();
    const expected = Buffer.from(integrity.slice(7), 'base64');
    if (expected.length !== digest.length || !timingSafeEqual(expected, digest)) throw new Error('archive integrity mismatch');
    const signatures = metadata.dist.signatures;
    if (!Array.isArray(signatures) || !signatures.length) throw new Error('registry signature is missing');
    const keysResponse = await fetchImpl('https://registry.npmjs.org/-/npm/v1/keys', { redirect: 'error', signal: AbortSignal.timeout(15000) });
    const keyDocument = JSON.parse((await readBounded(keysResponse, 256 * 1024)).toString('utf8'));
    if (!Array.isArray(keyDocument.keys)) throw new Error('registry signing keys unavailable');
    const signedMessage = Buffer.from(`${pkg.name}@${pkg.version}:${integrity}`);
    const signatureVerified = signatures.some((signature) => {
      const key = keyDocument.keys.find((candidate) => candidate.keyid === signature.keyid);
      if (!key || typeof key.key !== 'string' || typeof signature.sig !== 'string') return false;
      if (key.expires && (!Number.isFinite(Date.parse(key.expires)) || Date.parse(key.expires) <= Date.now())) return false;
      try {
        return verify('sha256', signedMessage, createPublicKey({ key: Buffer.from(key.key, 'base64'), format: 'der', type: 'spki' }), Buffer.from(signature.sig, 'base64'));
      } catch { return false; }
    });
    if (!signatureVerified) throw new Error('registry signature verification failed');
    const inspection = inspectArchive(archive, pkg);
    for (const hook of ['preinstall', 'install', 'postinstall']) {
      if ((inspection.lifecycleCommands[hook] || null) !== (metadata.scripts?.[hook] || null)) inspection.findings.push(`archive and registry disagree on ${hook}`);
    }
    const osvResponse = await fetchImpl('https://api.osv.dev/v1/query', {
      method: 'POST', redirect: 'error', signal: AbortSignal.timeout(15000),
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ package: { name: pkg.name, ecosystem: 'npm' }, version: pkg.version }),
    });
    const osv = JSON.parse((await readBounded(osvResponse, 2 * 1024 * 1024)).toString('utf8'));
    if (!osv || typeof osv !== 'object' || Array.isArray(osv) || (osv.vulns !== undefined && !Array.isArray(osv.vulns)) || osv.error) throw new Error('invalid vulnerability response');
    const advisories = (osv.vulns || []).map((entry) => {
      if (typeof entry.id !== 'string') throw new Error('invalid vulnerability record');
      return entry.id;
    });
    return { status: inspection.findings.length || advisories.length ? 'flagged' : 'reviewed', integrity, signatureVerified, ...inspection, advisories };
  } catch (error) {
    return { status: 'incomplete', reason: error.message };
  }
}
