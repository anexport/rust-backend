
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
