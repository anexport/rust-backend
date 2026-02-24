# AI Build Plan: Frontend

This document outlines the steps the AI should take to build out the Next.js frontend once the user has completed the initial setup.

## Phase 1: Authentication Implementation

1. **Auth0 Next.js Integration:**
   - Create `src/app/api/auth/[auth0]/route.ts`.
   - Ensure the handler initializes Auth0 properly and requests an Access Token for the `AUTH0_AUDIENCE` so it can be used with the Rust backend.
   - Example configuration:
     ```typescript
     import { handleAuth, handleLogin } from '@auth0/nextjs-auth0';

     export const GET = handleAuth({
       login: handleLogin({
         authorizationParams: {
           audience: process.env.AUTH0_AUDIENCE, // Critical for backend API
           scope: 'openid profile email offline_access',
         },
       }),
     });
     ```
2. **Global Auth Provide wrapper:**
   - Create a Client Component `src/components/AuthProvider.tsx` using `UserProvider` from `@auth0/nextjs-auth0/client`.
   - Wrap the main application layout (`src/app/layout.tsx`) in this provider.
3. **API Utility / Proxy:**
   - Because the frontend is split between Server Components and Client Components, create a central API fetching utility (`src/lib/api.ts`).
   - For **Server Components**, this utility should retrieve the token using `getAccessToken()` and attach it to the `Authorization: Bearer <token>` header.
   - For **Client Components**, it's safer to build Next.js Route Handlers (e.g., `src/app/api/proxy/[...path]/route.ts`) that attach the token and forward the request to the Rust backend, preventing exposing access tokens to the client unnecessarily, OR use the client SDK to get the token. A Next.js API route proxy is generally simpler and safer for client-side fetches.

## Phase 2: Core Layout and Navigation

1. **Navigation Bar (`src/components/Navbar.tsx`):**
   - Create a sticky header with links to:
     - Home (`/`)
     - Equipment (`/equipment`)
     - Messages (`/messages`)
   - Add conditional rendering for the user session:
     - If logged out: Show a "Log In" button pointing to `/api/auth/login`.
     - If logged in: Show the User's avatar with a dropdown menu linking to "Profile" (`/profile`) and "Log Out" (`/api/auth/logout`).
2. **Base Page Layouts:**
   - Ensure `src/app/page.tsx` introduces the user to the application.
   - Setup consistent shadcn/ui Card-based layouts.

## Phase 3: Profile and User Management

1. **Profile Page (`src/app/profile/page.tsx`):**
   - Server-side render the user's details using data fetched from the backend `GET /api/auth/me`.
   - Build a shadcn Form to allow updating the user profile.
   - Send `PUT /api/users/{user_id}`.
2. **State Management:** Implement revalidation (`revalidatePath`) after successful profile updates.

## Phase 4: Equipment Marketplace

1. **Equipment Listing (`src/app/equipment/page.tsx`):**
   - Fetch and display a list of available equipment (`GET /api/equipment`).
   - Use shadcn Cards to build a visually appealing grid.
   - Include category filters (`GET /api/categories`).
2. **Equipment Details (`src/app/equipment/[id]/page.tsx`):**
   - Fetch details for a specific equipment item.
   - Show photos, descriptions, and rental rates.
3. **Create Listing:**
   - Build a "Create Listing" dialog or dedicated page (`/equipment/new`).
   - Use shadcn Form with validation to POST to `/api/equipment`.

## Phase 5: Real-time Chat (WebSockets)

1. **Conversations View (`src/app/messages/page.tsx`):**
   - Fetch the user's active conversations (`GET /api/conversations`).
   - Display them in a sidebar or list view.
2. **Active Chat Window (`src/app/messages/[id]/page.tsx`):**
   - Fetch historical messages (`GET /api/conversations/{id}/messages`).
   - Render the chat UI.
3. **WebSocket Integration (`src/hooks/useChatWebSocket.ts`):**
   - Build a custom React Hook to manage the `WebSocket` connection.
   - To connect, you will need the raw Auth0 token. You may need a specific Next.js API route (e.g., `GET /api/auth/token`) to safely pass the token to the client, or use the `bearer,<token>` subprotocol.
   - The hook should handle receiving JSON payloads (`message`, `typing`, `read`).
   - Provide a `sendMessage` function to dispatch JSON envelopes to the backend `/ws` endpoint.
   - Render incoming messages in real-time in the Chat Window.

## Phase 6: Polish

1. **Error Handling:**
   - Integrate `toast` from shadcn to show success/error notifications on form submissions and API failures.
2. **Loading States:**
   - Add `loading.tsx` files leveraging shadcn Skeletons for smoother transitions.
3. **Validation Verification:**
   - Test all user flows to ensure data displays correctly and API endpoints return expected successes.