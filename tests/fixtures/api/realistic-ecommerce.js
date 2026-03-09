// Realistic fixture: A vibe-coded e-commerce app.
// This represents what AI tools ACTUALLY generate.
// Every vulnerability here is something we've seen in real apps.

import { PrismaClient } from '@prisma/client';
import Stripe from 'stripe';

const prisma = new PrismaClient();
const stripe = new Stripe("sk_test_4eC70MC0nfigFak3abc123def456");

// ❌ IDOR: No ownership check on order retrieval
export async function GET(req, { params }) {
  const order = await prisma.order.findUnique({
    where: { id: params.id }
  });
  return Response.json(order);
}

// ❌ Mass assignment: Full body to create
// ❌ Plaintext password
// ❌ No input validation
export async function POST(req) {
  const body = await req.json();
  const user = await prisma.user.create({ data: body });
  return Response.json(user);
}

// ❌ Price calculated client-side, trusted by server
// (This would be in a component file - included here for reference)
// const totalPrice = items.reduce((sum, item) => sum + item.price * item.quantity, 0);
// fetch('/api/checkout', { body: JSON.stringify({ total: totalPrice }) })

// ❌ No rate limiting on paid API
export async function generateDescription(req) {
  const { prompt } = await req.json();
  const openai = new OpenAI();
  const response = await openai.chat.completions.create({
    model: "gpt-4",
    messages: [{ role: "user", content: prompt }],
  });
  return Response.json(response);
}

// ❌ File upload with no validation
export async function uploadHandler(req) {
  const formData = await req.formData();
  const file = formData.get("file");
  // No type check, no size check, just save it
  await writeFile(`uploads/${file.name}`, Buffer.from(await file.arrayBuffer()));
  return Response.json({ url: `/uploads/${file.name}` });
}

// ❌ Path traversal in download
export async function downloadHandler(req) {
  const url = new URL(req.url);
  const filename = url.searchParams.get("file");
  const data = fs.readFileSync(`uploads/${filename}`);
  return new Response(data);
}
