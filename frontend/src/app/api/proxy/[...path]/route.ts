import { auth0 } from '@/lib/auth0';
import { NextRequest, NextResponse } from 'next/server';

const API_BASE_URL = process.env.API_URL || process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8080';
const PROXY_TIMEOUT_MS = 15000;

function isValidPathSegment(segment: string): boolean {
  if (segment === '.' || segment === '..') {
    return false;
  }
  if (segment.includes('/') || segment.includes('\\')) {
    return false;
  }
  return /^[\w.-]+$/.test(segment);
}

async function handler(req: NextRequest, { params }: { params: Promise<{ path: string[] }> }) {
  const { path } = await params;
  if (!Array.isArray(path) || path.length === 0 || path.some((segment) => !isValidPathSegment(segment))) {
    return NextResponse.json({ error: 'Invalid proxy path' }, { status: 400 });
  }

  const pathString = `/${path.join('/')}`;

  let token;
  const proxyRes = new NextResponse();
  try {
    const { token: accessToken } = await auth0.getAccessToken(req, proxyRes);
    token = accessToken;
  } catch (error) {
    console.warn('Proxy request without access token', error);
  }

  const headers = new Headers();
  req.headers.forEach((value, key) => {
    const lowerKey = key.toLowerCase();
    if (!['host', 'content-length', 'connection'].includes(lowerKey)) {
      headers.set(key, value);
    }
  });

  if (token) {
    headers.set('Authorization', `Bearer ${token}`);
  }

  const searchParams = req.nextUrl.searchParams.toString();
  const url = `${API_BASE_URL}${pathString}${searchParams ? `?${searchParams}` : ''}`;

  const fetchOptions: RequestInit & { duplex?: string } = {
    method: req.method,
    headers,
  };

  if (req.method !== 'GET' && req.method !== 'HEAD') {
    fetchOptions.body = req.body;
    fetchOptions.duplex = 'half';
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), PROXY_TIMEOUT_MS);
  fetchOptions.signal = controller.signal;

  let res: Response;
  try {
    res = await fetch(url, fetchOptions);
  } catch (error) {
    const isAbort = error instanceof Error && error.name === 'AbortError';
    return NextResponse.json(
      { error: isAbort ? 'Upstream request timed out' : 'Failed to reach upstream service' },
      { status: isAbort ? 504 : 502 },
    );
  } finally {
    clearTimeout(timeoutId);
  }

  const responseHeaders = new Headers(res.headers);

  // Propagate any cookies set by Auth0 (e.g., token refresh)
  proxyRes.headers.forEach((value, key) => {
    if (key.toLowerCase() === 'set-cookie') {
      responseHeaders.append(key, value);
    }
  });

  return new NextResponse(res.body, {
    status: res.status,
    statusText: res.statusText,
    headers: responseHeaders,
  });
}

export const GET = handler;
export const POST = handler;
export const PUT = handler;
export const PATCH = handler;
export const DELETE = handler;
