import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { clientBundleSecrets } from '../../src/rules/client-bundle-secrets.js';
import { clientOnlyAuth } from '../../src/rules/client-only-auth.js';
import { sensitiveBrowserStorage } from '../../src/rules/sensitive-browser-storage.js';
import { consoleDataLeak } from '../../src/rules/console-data-leak.js';
import { sourceMapsExposed } from '../../src/rules/source-maps-exposed.js';
import { clientSideTrust } from '../../src/rules/client-side-trust.js';
import { apiDataOverfetch } from '../../src/rules/api-data-overfetch.js';

function makeFile(relativePath, content) {
  return {
    path: `/project/${relativePath}`,
    relativePath,
    content,
    lines: content.split('\n'),
  };
}

// ─── Client Bundle Secrets ────────────────────────────────────────────────────

describe('client-bundle-secrets', () => {
  it('detects hardcoded API keys in client components', () => {
    const file = makeFile('src/components/Chat.jsx', 'const apiKey = "sk-proj-abc123def456ghi789jkl012"');
    const findings = clientBundleSecrets.check(file);
    assert.ok(findings.length > 0, 'Should detect hardcoded API key in client file');
  });

  it('skips server-side files', () => {
    const file = makeFile('api/chat.js', 'const apiKey = "sk-proj-abc123def456ghi789jkl012"');
    const findings = clientBundleSecrets.check(file);
    assert.equal(findings.length, 0, 'Should skip server files');
  });

  it('detects client env var secret references', () => {
    const file = makeFile('src/app/page.tsx', 'const key = process.env.NEXT_PUBLIC_SECRET_KEY');
    const findings = clientBundleSecrets.check(file);
    assert.ok(findings.length > 0, 'Should detect NEXT_PUBLIC_SECRET in client file');
  });
});

// ─── Client-Only Auth ─────────────────────────────────────────────────────────

describe('client-only-auth', () => {
  it('detects client-side auth redirects', () => {
    const file = makeFile('src/pages/Dashboard.jsx', 'if (!user) return <Navigate to="/login" />');
    const findings = clientOnlyAuth.check(file);
    assert.ok(findings.length > 0, 'Should detect client-only auth redirect');
  });

  it('detects conditional admin rendering', () => {
    const file = makeFile('src/components/Panel.tsx', '{isAdmin && (<AdminPanel />)}');
    const findings = clientOnlyAuth.check(file);
    assert.ok(findings.length > 0, 'Should detect client-side admin gate');
  });

  it('skips non-component files', () => {
    const file = makeFile('api/users.js', 'if (!user) return res.status(401)');
    const findings = clientOnlyAuth.check(file);
    assert.equal(findings.length, 0, 'Should skip API files');
  });
});

// ─── Sensitive Browser Storage ────────────────────────────────────────────────

describe('sensitive-browser-storage', () => {
  it('detects token in localStorage', () => {
    const file = makeFile('src/auth.js', 'localStorage.setItem("authToken", token)');
    const findings = sensitiveBrowserStorage.check(file);
    assert.ok(findings.length > 0, 'Should detect token in localStorage');
    assert.equal(findings[0].severity, 'critical');
  });

  it('detects JWT in sessionStorage', () => {
    const file = makeFile('src/login.js', 'sessionStorage.setItem("jwt", response.token)');
    const findings = sensitiveBrowserStorage.check(file);
    assert.ok(findings.length > 0, 'Should detect JWT in sessionStorage');
  });

  it('ignores non-sensitive storage', () => {
    const file = makeFile('src/theme.js', 'localStorage.setItem("theme", "dark")');
    const findings = sensitiveBrowserStorage.check(file);
    assert.equal(findings.length, 0, 'Should not flag theme storage');
  });
});

// ─── Console Data Leak ────────────────────────────────────────────────────────

describe('console-data-leak', () => {
  it('detects logging tokens', () => {
    const file = makeFile('src/api.js', 'console.log("token:", token)');
    const findings = consoleDataLeak.check(file);
    assert.ok(findings.length > 0, 'Should detect token in console.log');
  });

  it('detects logging request headers', () => {
    const file = makeFile('src/middleware.js', 'console.log("headers:", req.headers)');
    const findings = consoleDataLeak.check(file);
    assert.ok(findings.length > 0, 'Should detect req.headers logging');
  });

  it('skips test files', () => {
    const file = makeFile('src/__tests__/auth.test.js', 'console.log("token:", token)');
    const findings = consoleDataLeak.check(file);
    assert.equal(findings.length, 0, 'Should skip test files');
  });
});

// ─── Source Maps Exposed ──────────────────────────────────────────────────────

describe('source-maps-exposed', () => {
  it('detects sourcemap:true in vite config', () => {
    const file = makeFile('vite.config.js', 'build: { sourcemap: true }');
    const findings = sourceMapsExposed.check(file);
    assert.ok(findings.length > 0, 'Should detect sourcemap: true');
  });

  it('detects productionBrowserSourceMaps in next config', () => {
    const file = makeFile('next.config.js', 'productionBrowserSourceMaps: true');
    const findings = sourceMapsExposed.check(file);
    assert.ok(findings.length > 0, 'Should detect Next.js production source maps');
  });

  it('skips non-config files', () => {
    const file = makeFile('src/utils.js', 'sourcemap: true');
    const findings = sourceMapsExposed.check(file);
    assert.equal(findings.length, 0, 'Should skip non-config files');
  });
});

// ─── Client-Side Trust ────────────────────────────────────────────────────────

describe('client-side-trust', () => {
  it('detects client-side price calculation', () => {
    const file = makeFile('src/components/Cart.jsx', 'const totalPrice = items.reduce((sum, i) => sum + i.price, 0)');
    const findings = clientSideTrust.check(file);
    assert.ok(findings.length > 0, 'Should detect client-side price calc');
  });

  it('detects hidden form fields with sensitive names', () => {
    const file = makeFile('src/pages/checkout.html', '<input type="hidden" name="price" value="9.99">');
    const findings = clientSideTrust.check(file);
    assert.ok(findings.length > 0, 'Should detect hidden price field');
  });

  it('skips server files', () => {
    const file = makeFile('api/checkout.js', 'const totalPrice = calculateServerSide(cart)');
    const findings = clientSideTrust.check(file);
    assert.equal(findings.length, 0, 'Should skip API files');
  });
});

// ─── API Data Overfetch ───────────────────────────────────────────────────────

describe('api-data-overfetch', () => {
  it('detects spreading user object into response', () => {
    const file = makeFile('api/users/[id].js', 'return Response.json({ ...user })');
    const findings = apiDataOverfetch.check(file);
    assert.ok(findings.length > 0, 'Should detect user object spread in response');
  });

  it('detects Prisma without select', () => {
    const file = makeFile('api/profile.js', 'const user = await prisma.user.findUnique({ where: { id } })');
    const findings = apiDataOverfetch.check(file);
    assert.ok(findings.length > 0, 'Should detect Prisma query without select');
  });

  it('skips non-API files', () => {
    const file = makeFile('src/components/Profile.jsx', 'const user = await prisma.user.findUnique({ where: { id } })');
    const findings = apiDataOverfetch.check(file);
    assert.equal(findings.length, 0, 'Should skip client files');
  });
});
