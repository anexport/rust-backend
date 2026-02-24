import { auth0 } from './auth0';

const API_BASE_URL = process.env.API_URL || process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8080';

export async function fetchServer(path: string, options: RequestInit = {}): Promise<Response> {
  let token: string | null = null;

  try {
    const { token: accessToken } = await auth0.getAccessToken();
    token = accessToken ?? null;
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

  return fetch(`${API_BASE_URL}${path}`, {
    ...options,
    headers: reqHeadersForFetch,
  });
}
