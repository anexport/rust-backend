import { getAccessToken } from '@auth0/nextjs-auth0';
import { NextRequest, NextResponse } from 'next/server';

export async function GET(req: NextRequest) {
  const res = new NextResponse();
  try {
    const { accessToken } = await getAccessToken(req, res);
    const response = NextResponse.json({ accessToken });
    
    // Propagate any cookies set by Auth0
    res.headers.forEach((value, key) => {
      response.headers.append(key, value);
    });

    return response;
  } catch (error) {
    return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });
  }
}
