import { getAccessToken } from '@auth0/nextjs-auth0';
import { NextRequest, NextResponse } from 'next/server';

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8080';

async function handler(req: NextRequest, { params }: { params: Promise<{ path: string[] }> }) {
  const { path } = await params;
  const pathString = `/${path.join('/')}`;
  
  let token;
  const proxyRes = new NextResponse();
  try {
    const { accessToken } = await getAccessToken(req, proxyRes);
    token = accessToken;
  } catch (error) {
    // Ignore error
  }

  const headers = new Headers();
  req.headers.forEach((value, key) => {
    if (key.toLowerCase() !== 'host') {
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

  const res = await fetch(url, fetchOptions);

  const responseHeaders = new Headers(res.headers);
  responseHeaders.delete('content-encoding');

  // Propagate any cookies set by Auth0 (e.g., token refresh)
  proxyRes.headers.forEach((value, key) => {
    responseHeaders.append(key, value);
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
