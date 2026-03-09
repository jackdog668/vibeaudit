import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { pathTraversal } from '../../src/rules/path-traversal.js';
import { insecureJwt } from '../../src/rules/insecure-jwt.js';
import { plaintextPasswords } from '../../src/rules/plaintext-passwords.js';
import { insecureRandomness } from '../../src/rules/insecure-randomness.js';
import { insecureCookies } from '../../src/rules/insecure-cookies.js';
import { ssrfVulnerability } from '../../src/rules/ssrf-vulnerability.js';
import { prototypePollution } from '../../src/rules/prototype-pollution.js';
import { missingGitignore } from '../../src/rules/missing-gitignore.js';
import { timingAttack } from '../../src/rules/timing-attack.js';
import { corsCredentials } from '../../src/rules/cors-credentials.js';
import { noAccountLockout } from '../../src/rules/no-account-lockout.js';
import { unsafeRedirect } from '../../src/rules/unsafe-redirect.js';

function makeFile(relativePath, content) {
  return {
    path: `/project/${relativePath}`,
    relativePath,
    content,
    lines: content.split('\n'),
  };
}

// ─── Path Traversal ───────────────────────────────────────────────────────────

describe('path-traversal', () => {
  it('detects fs.readFile with user input', () => {
    const file = makeFile('api/download.js', 'async function handler(req) { fs.readFile(`uploads/${req.query.filename}`, (e,d) => {}) }');
    const findings = pathTraversal.check(file);
    assert.ok(findings.length > 0, 'Should detect path traversal');
  });

  it('passes with path.basename sanitization', () => {
    const file = makeFile('api/download.js', [
      'async function handler(req) {',
      '  const safeName = path.basename(req.query.filename)',
      '  fs.readFile(`uploads/${safeName}`, (e,d) => {})',
      '}',
    ].join('\n'));
    const findings = pathTraversal.check(file);
    assert.equal(findings.length, 0, 'Should pass with basename');
  });
});

// ─── Insecure JWT ─────────────────────────────────────────────────────────────

describe('insecure-jwt', () => {
  it('detects weak JWT secret', () => {
    const file = makeFile('api/auth.js', 'const token = jwt.sign(payload, "secret")');
    const findings = insecureJwt.check(file);
    assert.ok(findings.length > 0, 'Should detect weak JWT secret');
  });

  it('detects jwt.verify without algorithms', () => {
    const file = makeFile('api/auth.js', 'const decoded = jwt.verify(token, secret)');
    const findings = insecureJwt.check(file);
    const algoFinding = findings.find((f) => f.message.includes('algorithms'));
    assert.ok(algoFinding, 'Should detect missing algorithm pinning');
  });

  it('passes with env var secret', () => {
    const file = makeFile('api/auth.js', [
      'const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: "1h", algorithms: ["HS256"] })',
    ].join('\n'));
    const findings = insecureJwt.check(file);
    const weakSecret = findings.find((f) => f.message.includes('weak'));
    assert.ok(!weakSecret, 'Should not flag env var secret');
  });
});

// ─── Plaintext Passwords ──────────────────────────────────────────────────────

describe('plaintext-passwords', () => {
  it('detects raw password in create', () => {
    const file = makeFile('api/register.js', 'async function register(req) { const user = await prisma.user.create({ data: { email, password: body.password } }) }');
    const findings = plaintextPasswords.check(file);
    assert.ok(findings.length > 0, 'Should detect plaintext password');
  });

  it('detects === password comparison', () => {
    const file = makeFile('api/login.js', 'async function login(req) { if (password === user.password) { grant() } }');
    const findings = plaintextPasswords.check(file);
    assert.ok(findings.length > 0, 'Should detect === password comparison');
  });

  it('passes with bcrypt', () => {
    const file = makeFile('api/register.js', [
      'const hash = await bcrypt.hash(password, 12)',
      'await prisma.user.create({ data: { email, password: hash } })',
    ].join('\n'));
    const findings = plaintextPasswords.check(file);
    assert.equal(findings.length, 0, 'Should pass with bcrypt');
  });
});

// ─── Insecure Randomness ──────────────────────────────────────────────────────

describe('insecure-randomness', () => {
  it('detects Math.random for token generation', () => {
    const file = makeFile('src/utils.js', 'const token = Math.random().toString(36).slice(2)');
    const findings = insecureRandomness.check(file);
    assert.ok(findings.length > 0, 'Should detect Math.random for token');
  });

  it('ignores Math.random for non-security use', () => {
    const file = makeFile('src/game.js', 'const color = Math.random() > 0.5 ? "red" : "blue"');
    const findings = insecureRandomness.check(file);
    assert.equal(findings.length, 0, 'Should ignore non-security Math.random');
  });
});

// ─── Insecure Cookies ─────────────────────────────────────────────────────────

describe('insecure-cookies', () => {
  it('detects cookie with no options', () => {
    const file = makeFile('api/login.js', 'res.cookie("session", token)');
    const findings = insecureCookies.check(file);
    assert.ok(findings.length > 0, 'Should detect cookie with no options');
  });

  it('passes with all flags set', () => {
    const file = makeFile('api/login.js', 'res.cookie("session", token, { httpOnly: true, secure: true, sameSite: "lax" })');
    const findings = insecureCookies.check(file);
    assert.equal(findings.length, 0, 'Should pass with all flags');
  });
});

// ─── SSRF ─────────────────────────────────────────────────────────────────────

describe('ssrf-vulnerability', () => {
  it('detects fetch with user-provided URL', () => {
    const file = makeFile('api/preview.js', 'async function handler(req) { const res = await fetch(req.body.url) }');
    const findings = ssrfVulnerability.check(file);
    assert.ok(findings.length > 0, 'Should detect SSRF');
  });

  it('passes with allowlist', () => {
    const file = makeFile('api/preview.js', [
      'async function handler(req) {',
      '  const allowedHosts = ["example.com"]',
      '  const res = await fetch(req.body.url)',
      '}',
    ].join('\n'));
    const findings = ssrfVulnerability.check(file);
    assert.equal(findings.length, 0, 'Should pass with allowlist');
  });
});

// ─── Prototype Pollution ──────────────────────────────────────────────────────

describe('prototype-pollution', () => {
  it('detects lodash merge with user input', () => {
    const file = makeFile('api/settings.js', '_.merge(config, req.body)');
    const findings = prototypePollution.check(file);
    assert.ok(findings.length > 0, 'Should detect prototype pollution');
  });

  it('detects __proto__ access', () => {
    const file = makeFile('src/utils.js', 'obj.__proto__.isAdmin = true');
    const findings = prototypePollution.check(file);
    assert.ok(findings.length > 0, 'Should detect __proto__ access');
  });
});

// ─── Missing .gitignore ──────────────────────────────────────────────────────

describe('missing-gitignore', () => {
  it('flags missing .env in gitignore', () => {
    const file = makeFile('.gitignore', 'node_modules/\n.DS_Store');
    const findings = missingGitignore.check(file);
    const envMissing = findings.find((f) => f.message.includes('.env'));
    assert.ok(envMissing, 'Should flag missing .env');
    assert.equal(envMissing.severity, 'critical');
  });

  it('passes when .env is ignored', () => {
    const file = makeFile('.gitignore', '.env\nnode_modules/\n.DS_Store');
    const findings = missingGitignore.check(file);
    const envMissing = findings.find((f) => f.message.includes('.env') && f.severity === 'critical');
    assert.ok(!envMissing, 'Should pass when .env is in gitignore');
  });

  it('only checks .gitignore files', () => {
    const file = makeFile('src/app.js', 'console.log("hello")');
    const findings = missingGitignore.check(file);
    assert.equal(findings.length, 0);
  });
});

// ─── Timing Attack ────────────────────────────────────────────────────────────

describe('timing-attack', () => {
  it('detects token === comparison', () => {
    const file = makeFile('api/verify.js', 'if (token === expectedToken) { grant() }');
    const findings = timingAttack.check(file);
    assert.ok(findings.length > 0, 'Should detect timing-vulnerable comparison');
  });

  it('passes with timingSafeEqual', () => {
    const file = makeFile('api/verify.js', [
      'const match = crypto.timingSafeEqual(Buffer.from(token), Buffer.from(expected))',
      'if (token === expectedToken) { grant() }',
    ].join('\n'));
    const findings = timingAttack.check(file);
    assert.equal(findings.length, 0, 'Should pass with timingSafeEqual');
  });
});

// ─── CORS Credentials ────────────────────────────────────────────────────────

describe('cors-credentials', () => {
  it('detects credentials:true with localhost origin', () => {
    const file = makeFile('server.js', [
      'app.use(cors({',
      '  origin: "http://localhost:3000",',
      '  credentials: true',
      '}))',
    ].join('\n'));
    const findings = corsCredentials.check(file);
    assert.ok(findings.length > 0, 'Should detect localhost + credentials');
  });
});

// ─── No Account Lockout ──────────────────────────────────────────────────────

describe('no-account-lockout', () => {
  it('detects login route without lockout', () => {
    const file = makeFile('api/auth/login.js', [
      'app.post("/api/login", async (req, res) => {',
      '  const valid = await bcrypt.compare(req.body.password, user.hash)',
      '  if (valid) res.json({ token })',
      '})',
    ].join('\n'));
    const findings = noAccountLockout.check(file);
    assert.ok(findings.length > 0, 'Should detect missing lockout');
  });

  it('passes with failed attempt tracking', () => {
    const file = makeFile('api/auth/login.js', [
      'app.post("/api/login", async (req, res) => {',
      '  if (failedAttempts > 5) return res.status(429)',
      '  const valid = await bcrypt.compare(req.body.password, user.hash)',
      '})',
    ].join('\n'));
    const findings = noAccountLockout.check(file);
    assert.equal(findings.length, 0, 'Should pass with attempt tracking');
  });
});

// ─── Unsafe Redirect ─────────────────────────────────────────────────────────

describe('unsafe-redirect', () => {
  it('detects redirect from query param', () => {
    const file = makeFile('api/auth/callback.js', 'res.redirect(req.query.returnTo)');
    const findings = unsafeRedirect.check(file);
    assert.ok(findings.length > 0, 'Should detect unsafe redirect');
  });

  it('passes with startsWith validation', () => {
    const file = makeFile('api/auth/callback.js', [
      'const url = req.query.returnTo',
      'if (url.startsWith("/")) res.redirect(url)',
    ].join('\n'));
    const findings = unsafeRedirect.check(file);
    assert.equal(findings.length, 0, 'Should pass with relative URL check');
  });
});
