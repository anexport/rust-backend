import { auth0 } from '@/lib/auth0';
import { NextRequest, NextResponse } from 'next/server';

export async function GET(req: NextRequest) {
  const origin = req.headers.get('origin');
  if (origin && origin !== req.nextUrl.origin) {
    return NextResponse.json({ error: 'Forbidden origin' }, { status: 403 });
  }

  const res = new NextResponse();
  try {
    const { token: accessToken } = await auth0.getAccessToken(req, res);
    if (!accessToken) {
      return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });
    }

    const response = NextResponse.json({ accessToken });

    response.headers.set('Cache-Control', 'no-store');

    // Propagate any cookies set by Auth0
    res.headers.forEach((value, key) => {
      if (key.toLowerCase() === 'set-cookie') {
        response.headers.append(key, value);
      }
    });

    return response;
  } catch {
    return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });
  }
}
