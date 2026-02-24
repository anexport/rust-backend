import { auth0 } from '@/lib/auth0';

const API_BASE_URL = process.env.API_URL || process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8080';

export async function fetchServer(path: string, options: RequestInit = {}) {
  let token;
  try {
    const { headers } = await import('next/headers');
    const { NextRequest, NextResponse } = await import('next/server');

    // Await Next.js 15+ async headers
    const h = await headers();

    // Reconstruct a dummy request with current headers/cookies
    // so Auth0 SDK doesn't fall back to calling next/headers.cookies() synchronously.
    const reqHeaders = new Headers(h);
    const req = new NextRequest(new URL('http://localhost:3000'), {
      headers: reqHeaders,
    });

    const res = new NextResponse();
    const { token: accessToken } = await auth0.getAccessToken(req, res);
    token = accessToken;
  } catch (error) {
    console.warn('fetchServer proceeding without access token', error);
  }

  const reqHeadersForFetch = new Headers(options.headers);
  if (token) {
    reqHeadersForFetch.set('Authorization', `Bearer ${token}`);
  }

  if (!reqHeadersForFetch.has('Content-Type') && !(options.body instanceof FormData)) {
    reqHeadersForFetch.set('Content-Type', 'application/json');
  }

  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...options,
    headers: reqHeadersForFetch,
  });

  return response;
}

export async function fetchClient(path: string, options: RequestInit = {}) {
  const reqHeadersForFetch = new Headers(options.headers);
  if (!reqHeadersForFetch.has('Content-Type') && !(options.body instanceof FormData)) {
    reqHeadersForFetch.set('Content-Type', 'application/json');
  }

  const response = await fetch(`/api/proxy${path}`, {
    ...options,
    headers: reqHeadersForFetch,
  });
  return response;
}
