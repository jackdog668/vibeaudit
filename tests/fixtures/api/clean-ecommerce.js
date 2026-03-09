// Fixture: Properly secured e-commerce API. ZERO findings expected.
// Every security pattern is implemented correctly.

import { getServerSession } from 'next-auth';
import { rateLimit } from '@/lib/rate-limit';
import { z } from 'zod';
import bcrypt from 'bcrypt';
import crypto from 'crypto';
import path from 'path';

const UPLOADS_DIR = path.resolve('./uploads');

// ✅ Auth + Authorization (ownership check)
export async function GET(req, { params }) {
  const session = await getServerSession();
  if (!session) return Response.json({ error: 'Unauthorized' }, { status: 401 });

  const order = await prisma.order.findUnique({
    where: { id: params.id },
    select: { id: true, total: true, status: true, userId: true },
  });

  if (order.userId !== session.user.id) {
    return Response.json({ error: 'Forbidden' }, { status: 403 });
  }

  return Response.json(order);
}

// ✅ Schema validation, password hashing
const registerSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  name: z.string().min(1).max(100),
});

export async function register(req) {
  const session = await getServerSession();
  const body = await req.json();
  const { email, password, name } = registerSchema.parse(body);
  const hash = await bcrypt.hash(password, 12);
  const user = await prisma.user.create({ data: { email, password: hash, name } });
  return Response.json({ id: user.id, email: user.email, name: user.name });
}

// ✅ Rate limiting on paid API
export async function generateAI(req) {
  const session = await getServerSession();
  if (!session) return Response.json({ error: 'Unauthorized' }, { status: 401 });
  const limiter = await rateLimit(session.user.id);
  if (!limiter.ok) return Response.json({ error: 'Too many requests' }, { status: 429 });
  // ... AI call here
}

// ✅ File upload with validation
export async function upload(req) {
  const session = await getServerSession();
  if (!session) return Response.json({ error: 'Unauthorized' }, { status: 401 });
  const formData = await req.formData();
  const file = formData.get("image");
  const allowedTypes = ['image/jpeg', 'image/png', 'image/webp'];
  if (!allowedTypes.includes(file.type)) {
    return Response.json({ error: 'Invalid file type' }, { status: 400 });
  }
  if (file.size > 5 * 1024 * 1024) {
    return Response.json({ error: 'File too large' }, { status: 400 });
  }
  // ... save file
}

// ✅ Path traversal prevention
export async function download(req) {
  const url = new URL(req.url);
  const filename = path.basename(url.searchParams.get("file"));
  const resolved = path.resolve(UPLOADS_DIR, filename);
  if (!resolved.startsWith(UPLOADS_DIR)) {
    return Response.json({ error: 'Forbidden' }, { status: 403 });
  }
  // ... serve file
}

// ✅ Proper error handling
export async function safeHandler(req) {
  try {
    const result = await doSomething();
    return Response.json(result);
  } catch (error) {
    console.error('Handler failed:', error);
    return Response.json({ error: 'Something went wrong' }, { status: 500 });
  }
}

// ✅ Secure token comparison
function verifyWebhookSignature(body, signature, secret) {
  const expected = crypto.createHmac('sha256', secret).update(body).digest('hex');
  return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
}

// ✅ Secure random token
function generateResetToken() {
  return crypto.randomBytes(32).toString('hex');
}
