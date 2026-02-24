import { getAccessToken } from '@auth0/nextjs-auth0';
import { cookies, headers } from 'next/headers';
import { NextRequest, NextResponse } from 'next/server';

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8080';

export async function fetchServer(path: string, options: RequestInit = {}) {
  let token;
  try {
    // Await Next.js 15+ async headers and cookies
    const h = await headers();
    const c = await cookies();

    // Reconstruct a dummy request with current headers/cookies 
    // so Auth0 SDK doesn't fall back to calling next/headers.cookies() synchronously.
    const reqHeaders = new Headers(h);
    const req = new NextRequest(new URL('http://localhost:3000'), {
      headers: reqHeaders,
    });
    
    const res = new NextResponse();
    const { accessToken } = await getAccessToken(req, res);
    token = accessToken;
  } catch (error) {
    // Proceed without token if not authenticated
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
