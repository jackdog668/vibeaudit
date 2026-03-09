// Fixture: A properly secured file. No findings expected.

import { getServerSession } from 'next-auth';
import { rateLimit } from '@/lib/rate-limit';

export async function POST(request) {
  // Auth check
  const session = await getServerSession();
  if (!session) {
    return Response.json({ error: 'Unauthorized' }, { status: 401 });
  }

  // Rate limiting
  const limiter = await rateLimit(session.user.id);
  if (!limiter.ok) {
    return Response.json({ error: 'Too many requests' }, { status: 429 });
  }

  try {
    const body = await request.json();
    // Input validation would go here
    return Response.json({ success: true });
  } catch {
    // Generic error - no details leaked
    return Response.json({ error: 'Something went wrong' }, { status: 500 });
  }
}
