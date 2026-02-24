Starting CodeRabbit review in plain text mode...

Connecting to review service
Setting up
Analyzing
Reviewing

============================================================================
File: frontend/src/app/admin/layout.tsx
Line: 42 to 47
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @frontend/src/app/admin/layout.tsx around lines 42 - 47, The current truncated email span uses a title attribute which is not accessible to touch/keyboard users; replace the title usage by wrapping the truncated span (the element rendering {user.email ?? 'unknown'}) with your accessible Tooltip component (or add an aria-label and tabIndex=0 plus keyboard/touch-visible tooltip behavior) so it exposes the full email on focus and touch as well as hover; ensure the Tooltip is triggered on focus and touch, and keep the existing classes (truncate, font-medium) and the fallback user.email ?? 'unknown' logic intact.



============================================================================
File: frontend/src/lib/auth0.ts
Line: 17
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @frontend/src/lib/auth0.ts at line 17, The appBaseUrl fallback is hard-coded to 'http://localhost:3000' which overrides the SDK's host-based inference when APP_BASE_URL and AUTH0_BASE_URL are missing; update the auth configuration in frontend/src/lib/auth0.ts to remove that hardcoded fallback for appBaseUrl (i.e., use process.env.APP_BASE_URL || process.env.AUTH0_BASE_URL or omit/set appBaseUrl to undefined) so the SDK can infer the base URL from the request host at runtime.



============================================================================
File: frontend/src/lib/auth0.ts
Line: 5 to 25
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @frontend/src/lib/auth0.ts around lines 5 - 25, The proxy for auth0 only implements a get trap so writes and reflective ops hit the empty target instead of _auth0; update the Proxy handler for auth0 (and retain lazy init of _auth0 inside the handler) to add at minimum a forwarding set trap that assigns properties to _auth0 and returns true, and a has trap that checks property existence on _auth0; alternatively replace the Proxy with an eager factory that initializes _auth0 via Auth0Client in a helper and export that instance directly if module-load env access is acceptable.



============================================================================
File: frontend/src/lib/server.ts
Line: 22 to 23
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @frontend/src/lib/server.ts around lines 22 - 23, The call to auth0.getAccessToken may return either { token } or { accessToken } depending on SDK version, so update the handling in the auth flow around auth0.getAccessToken to support both shapes: after calling auth0.getAccessToken(req, res) check for result.token and result.accessToken (or destructure both) and assign the existing token variable from whichever property is present, and add a fallback/log/error when neither is provided so you don't silently proceed unauthenticated; look for usages of auth0.getAccessToken, the token variable, and the accessToken destructuring to implement this fix.



============================================================================
File: frontend/src/lib/server.ts
Line: 3
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @frontend/src/lib/server.ts at line 3, The server module's API_BASE_URL currently falls back to NEXT_PUBLIC_API_URL which inlines into the client bundle and may route server→backend traffic externally; update the API_BASE_URL declaration (symbol: API_BASE_URL in frontend/src/lib/server.ts) to use only process.env.API_URL with the local default (e.g., const API_BASE_URL = process.env.API_URL || 'http://localhost:8080'), remove any reference to NEXT_PUBLIC_API_URL, and ensure this module is not imported into client-side code so the private env var isn't leaked.



============================================================================
File: frontend/src/lib/server.ts
Line: 3
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @frontend/src/lib/server.ts at line 3, The server-side constant API_BASE_URL in server.ts should not fall back to NEXT_PUBLIC_API_URL; remove the NEXT_PUBLIC_API_URL fallback and rely only on the server-only env var (process.env.API_URL) with the local default ('http://localhost:8080') so server traffic uses internal network addresses and no public var is inlined into client bundles. Update the API_BASE_URL assignment to read only process.env.API_URL (and the local default) and ensure any callers of API_BASE_URL continue to work with that change.



============================================================================
File: frontend/src/lib/server.ts
Line: 37 to 40
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @frontend/src/lib/server.ts around lines 37 - 40, The fetch call using ${API_BASE_URL}${path} in the server request is fragile and has no timeout; update the request in the function that calls fetch with API_BASE_URL, path, options, and reqHeadersForFetch to: 1) build the URL via the URL API (new URL(path, API_BASE_URL)) to avoid double/missing slashes and 2) add an AbortSignal timeout using AbortSignal.timeout(ms) (Node 18+/Next.js 15) and pass the signal into fetch options so hung upstream responses are aborted. Ensure you use the same options and reqHeadersForFetch when creating the final fetch call.



============================================================================
File: frontend/src/lib/server.ts
Line: 37 to 40
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @frontend/src/lib/server.ts around lines 37 - 40, The fetch call in server.ts using fetch(${API_BASE_URL}${path}, { ...options, headers: reqHeadersForFetch }) lacks a request timeout and uses fragile string concatenation for the URL; fix by constructing the request URL with the URL API (e.g., new URL(path, API_BASE_URL)) to avoid double slashes/malformed URLs and add an AbortSignal timeout (AbortSignal.timeout(ms)) or create an AbortController and attach its signal to the fetch options (merge into options and include reqHeadersForFetch) so the request is aborted after a sensible timeout (e.g., 5–10s); update the call site where response is awaited and ensure the signal is passed alongside existing options/headers.



Review completed: 8 findings ✔
