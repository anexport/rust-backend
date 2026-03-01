import { auth0 } from '@/lib/auth0';

const API_BASE_URL = process.env.API_URL || 'http://localhost:8080';

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

export async function fetchServer(path: string, options: RequestInit = {}): Promise<Response> {
  let token: string | null = null;

  try {
    const tokenResult = await auth0.getAccessToken();
    token = extractAccessToken(tokenResult);
    if (!token) {
      console.warn('fetchServer getAccessToken returned no token');
    }
  } catch (err) {
    // Log the error for debugging but proceed without access token
    console.warn('fetchServer proceeding without access token:', err);
  }

  const reqHeadersForFetch = new Headers(options.headers);
  if (token) {
    reqHeadersForFetch.set('Authorization', `Bearer ${token}`);
  }

  if (!reqHeadersForFetch.has('Content-Type') && !(options.body instanceof FormData)) {
    reqHeadersForFetch.set('Content-Type', 'application/json');
  }

  // Prepend /v1 if path starts with /api/ and doesn't already have it
  const adjustedPath = path.startsWith('/api/') && !path.startsWith('/api/v1/')
    ? path.replace('/api/', '/api/v1/')
    : path;

  const upstreamUrl = new URL(adjustedPath, API_BASE_URL);

  const fetchOptions: RequestInit = {
    ...options,
    headers: reqHeadersForFetch,
    signal: options.signal ?
      AbortSignal.any([options.signal, AbortSignal.timeout(10000)]) :
      AbortSignal.timeout(10000),
  };

  return fetch(upstreamUrl, fetchOptions);
}
