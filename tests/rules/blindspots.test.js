import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { idorVulnerability } from '../../src/rules/idor-vulnerability.js';
import { missingCsrf } from '../../src/rules/missing-csrf.js';
import { unsafeFileUpload } from '../../src/rules/unsafe-file-upload.js';
import { massAssignment } from '../../src/rules/mass-assignment.js';
import { unverifiedWebhook } from '../../src/rules/unverified-webhook.js';
import { noPagination } from '../../src/rules/no-pagination.js';

function makeFile(relativePath, content) {
  return {
    path: `/project/${relativePath}`,
    relativePath,
    content,
    lines: content.split('\n'),
  };
}

// ─── IDOR ─────────────────────────────────────────────────────────────────────

describe('idor-vulnerability', () => {
  it('detects ID from params with no ownership check', () => {
    const file = makeFile('api/users/[id].js', [
      'export async function GET(req, { params }) {',
      '  const user = await db.user.findUnique({ where: { id: params.id } })',
      '  return Response.json(user)',
      '}',
    ].join('\n'));
    const findings = idorVulnerability.check(file);
    assert.ok(findings.length > 0, 'Should detect IDOR — no ownership check');
  });

  it('passes when ownership is verified', () => {
    const file = makeFile('api/users/[id].js', [
      'export async function GET(req, { params }) {',
      '  const session = await getSession()',
      '  const user = await db.user.findUnique({ where: { id: params.id } })',
      '  if (user.userId !== session.user.id) return new Response(null, { status: 403 })',
      '  return Response.json(user)',
      '}',
    ].join('\n'));
    const findings = idorVulnerability.check(file);
    assert.equal(findings.length, 0, 'Should pass with ownership check');
  });

  it('skips non-API files', () => {
    const file = makeFile('src/components/Profile.jsx', 'const id = params.id');
    const findings = idorVulnerability.check(file);
    assert.equal(findings.length, 0, 'Should skip client files');
  });
});

// ─── CSRF ─────────────────────────────────────────────────────────────────────

describe('missing-csrf', () => {
  it('detects POST route with no CSRF', () => {
    const file = makeFile('api/transfer.js', [
      'app.post("/api/transfer", async (req, res) => {',
      '  await transferMoney(req.body)',
      '  res.json({ success: true })',
      '})',
    ].join('\n'));
    const findings = missingCsrf.check(file);
    assert.ok(findings.length > 0, 'Should detect missing CSRF');
  });

  it('passes with CSRF token', () => {
    const file = makeFile('api/transfer.js', [
      'import { csrfToken } from "./csrf"',
      'app.post("/api/transfer", async (req, res) => {',
      '  await transferMoney(req.body)',
      '})',
    ].join('\n'));
    const findings = missingCsrf.check(file);
    assert.equal(findings.length, 0, 'Should pass with CSRF');
  });

  it('passes with SameSite cookies', () => {
    const file = makeFile('api/auth.js', [
      'app.post("/api/login", (req, res) => {',
      '  res.cookie("session", token, { SameSite: "Strict" })',
      '})',
    ].join('\n'));
    const findings = missingCsrf.check(file);
    assert.equal(findings.length, 0, 'Should pass with SameSite cookie');
  });
});

// ─── File Upload ──────────────────────────────────────────────────────────────

describe('unsafe-file-upload', () => {
  it('detects upload handler without validation', () => {
    const file = makeFile('api/upload.js', [
      'async function handler(req) {',
      '  const formData = await req.formData()',
      '  const file = formData.get("file")',
      '  await saveToStorage(file)',
      '}',
    ].join('\n'));
    const findings = unsafeFileUpload.check(file);
    assert.ok(findings.length > 0, 'Should detect unsafe upload handler');
  });

  it('passes with proper validation', () => {
    const file = makeFile('api/upload.js', [
      'const upload = multer({',
      '  limits: { fileSize: 5 * 1024 * 1024 },',
      '  fileFilter: (req, file, cb) => {',
      '    if (file.mimetype.startsWith("image/")) cb(null, true)',
      '  }',
      '})',
    ].join('\n'));
    const findings = unsafeFileUpload.check(file);
    assert.equal(findings.length, 0, 'Should pass with file filter + size limit');
  });

  it('skips non-upload files', () => {
    const file = makeFile('src/components/Form.jsx', 'const x = 1');
    const findings = unsafeFileUpload.check(file);
    assert.equal(findings.length, 0, 'Should skip non-server files');
  });
});

// ─── Mass Assignment ──────────────────────────────────────────────────────────

describe('mass-assignment', () => {
  it('detects raw req.body in Prisma create', () => {
    const file = makeFile('api/users.js', [
      'export async function POST(req) {',
      '  const body = await req.json()',
      '  const user = await prisma.user.create({ data: body })',
      '  return Response.json(user)',
      '}',
    ].join('\n'));
    const findings = massAssignment.check(file);
    assert.ok(findings.length > 0, 'Should detect mass assignment');
  });

  it('detects Object.assign with req.body', () => {
    const file = makeFile('api/profile.js', [
      'async function handler(req, res) {',
      '  Object.assign(user, req.body)',
      '  await user.save()',
      '}',
    ].join('\n'));
    const findings = massAssignment.check(file);
    assert.ok(findings.length > 0, 'Should detect Object.assign mass assignment');
  });

  it('passes with destructuring (whitelist)', () => {
    const file = makeFile('api/users.js', [
      'export async function POST(req) {',
      '  const { name, email } = await request.json()',
      '  const user = await prisma.user.create({ data: { name, email } })',
      '}',
    ].join('\n'));
    const findings = massAssignment.check(file);
    assert.equal(findings.length, 0, 'Should pass with field destructuring');
  });

  it('passes with Zod validation', () => {
    const file = makeFile('api/users.js', [
      'import { z } from "zod"',
      'const schema = z.object({ name: z.string() })',
      'const data = schema.parse(req.body)',
      'await prisma.user.create({ data: req.body })',
    ].join('\n'));
    const findings = massAssignment.check(file);
    assert.equal(findings.length, 0, 'Should pass with Zod validation');
  });
});

// ─── Unverified Webhook ───────────────────────────────────────────────────────

describe('unverified-webhook', () => {
  it('detects Stripe webhook handler with no signature check', () => {
    const file = makeFile('api/webhooks/stripe.js', [
      'export async function POST(req) {',
      '  const event = await req.json()',
      '  if (event.type === "payment_intent.succeeded") {',
      '    await grantAccess(event.data.object.metadata.userId)',
      '  }',
      '}',
    ].join('\n'));
    const findings = unverifiedWebhook.check(file);
    assert.ok(findings.length > 0, 'Should detect unverified webhook');
  });

  it('passes with constructEvent verification', () => {
    const file = makeFile('api/webhooks/stripe.js', [
      'export async function POST(req) {',
      '  const sig = req.headers.get("stripe-signature")',
      '  const event = stripe.webhooks.constructEvent(body, sig, secret)',
      '  if (event.type === "payment_intent.succeeded") {',
      '    await grantAccess(event.data.object.metadata.userId)',
      '  }',
      '}',
    ].join('\n'));
    const findings = unverifiedWebhook.check(file);
    assert.equal(findings.length, 0, 'Should pass with signature verification');
  });

  it('skips non-webhook files', () => {
    const file = makeFile('api/users.js', [
      'export async function POST(req) {',
      '  return Response.json({ ok: true })',
      '}',
    ].join('\n'));
    const findings = unverifiedWebhook.check(file);
    assert.equal(findings.length, 0, 'Should skip non-webhook files');
  });
});

// ─── No Pagination ────────────────────────────────────────────────────────────

describe('no-pagination', () => {
  it('detects Prisma findMany with no take', () => {
    const file = makeFile('api/users.js', [
      'export async function GET() {',
      '  const users = await prisma.user.findMany({})',
      '  return Response.json(users)',
      '}',
    ].join('\n'));
    const findings = noPagination.check(file);
    assert.ok(findings.length > 0, 'Should detect unbounded findMany');
  });

  it('detects Firestore collection().get()', () => {
    const file = makeFile('api/posts.js', [
      'const snapshot = await db.collection("posts").get()',
    ].join('\n'));
    const findings = noPagination.check(file);
    assert.ok(findings.length > 0, 'Should detect unbounded Firestore get');
  });

  it('passes with pagination present', () => {
    const file = makeFile('api/users.js', [
      'const page = parseInt(req.query.page) || 1',
      'const pageSize = 20',
      'const users = await prisma.user.findMany({',
      '  take: pageSize,',
      '  skip: (page - 1) * pageSize',
      '})',
    ].join('\n'));
    const findings = noPagination.check(file);
    assert.equal(findings.length, 0, 'Should pass with pagination');
  });

  it('skips non-API files', () => {
    const file = makeFile('src/utils/db.js', 'await prisma.user.findMany({})');
    const findings = noPagination.check(file);
    assert.equal(findings.length, 0, 'Should skip non-API files');
  });
});
