import { auth0 } from '@/lib/auth0';
import { NextRequest, NextResponse } from 'next/server';

type AccessTokenResult = {
  token?: string;
  accessToken?: string;
};

function extractAccessToken(result: unknown): string | null {
  if (!result || typeof result !== 'object') {
    return null;
  }
  const tokenResult = result as AccessTokenResult;
  return tokenResult.token ?? tokenResult.accessToken ?? null;
}

export async function GET(req: NextRequest) {
  const origin = req.headers.get('origin');
  if (origin && origin !== req.nextUrl.origin) {
    return NextResponse.json({ error: 'Forbidden origin' }, { status: 403 });
  }

  const res = new NextResponse();
  try {
    const accessToken = extractAccessToken(await auth0.getAccessToken(req, res));
    if (!accessToken) {
      console.warn('/api/auth/token getAccessToken returned no token value');
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
