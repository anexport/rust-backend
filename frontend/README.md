# Frontend Documentation

Next.js 16.1.6 frontend for the equipment rental platform, using App Router, TypeScript, and Auth0 authentication.

---

## Technology Stack

| Technology | Version | Purpose |
|-----------|---------|---------|
| Next.js | 16.1.6 | React framework with App Router |
| React | 19.2.4 | UI library |
| TypeScript | Latest | Type safety |
| Auth0 SDK | 4.15.0 | Authentication |
| Tailwind CSS | Latest | Styling |
| shadcn/ui | Latest | UI component library |
| Radix UI | 1.4.3 | Headless UI primitives |
| React Hook Form | 7.71.2 | Form management |
| Zod | 4.3.6 | Schema validation |
| Lucide React | 0.575.0 | Icons |
| next-themes | 0.4.6 | Dark/light theme |

---

## Project Structure

```
frontend/
├── src/
│   ├── app/                    # Next.js App Router pages
│   │   ├── layout.tsx          # Root layout (Navbar, Footer, Providers)
│   │   ├── page.tsx            # Home page
│   │   ├── auth/               # Auth routes
│   │   ├── admin/              # Admin pages
│   │   ├── equipment/          # Equipment pages
│   │   ├── messages/           # Messaging pages
│   │   └── profile/            # User profile
│   ├── components/             # React components
│   │   ├── ui/                # shadcn/ui components
│   │   ├── Navbar.tsx
│   │   ├── Footer.tsx
│   │   ├── AuthProvider.tsx
│   │   └── theme-provider.tsx
│   ├── lib/                   # Utilities
│   │   ├── api.ts             # Client-side API client
│   │   ├── auth0.ts           # Auth0 SDK instance
│   │   ├── server.ts          # Server-side fetch
│   │   ├── adminGuard.ts      # Admin route guard
│   │   └── utils.ts          # Utility functions
│   ├── hooks/                 # Custom React hooks
│   │   └── useChatWebSocket.ts # WebSocket hook
│   ├── actions/               # Server Actions
│   │   └── profile/actions.ts
│   └── styles/               # Global styles
├── components.json           # shadcn/ui configuration
├── next.config.ts           # Next.js configuration
├── tailwind.config.ts      # Tailwind CSS configuration
├── tsconfig.json           # TypeScript configuration
└── package.json           # Dependencies and scripts
```

---

## Pages & Routes

| Route | Path | Type | Description |
|-------|------|------|-------------|
| Home | `/` | Server | Featured equipment listings |
| Profile | `/profile` | Server + Client | User profile editing |
| Equipment List | `/equipment` | Server | Browse all equipment |
| Equipment Detail | `/equipment/[id]` | Server | Single equipment view |
| New Equipment | `/equipment/new` | Client | Create equipment form |
| Messages List | `/messages` | Server | User conversations |
| Conversation | `/messages/[id]` | Server + Client | Chat interface |
| Admin Dashboard | `/admin` | Server | Admin overview |
| Admin Users | `/admin/users` | Server + Client | User management |
| Admin Equipment | `/admin/equipment` | Server + Client | Equipment management |
| Admin Categories | `/admin/categories` | Server + Client | Category management |

---

## Authentication Flow

### Auth0 Integration

The frontend uses `@auth0/nextjs-auth0` SDK for authentication.

**Configuration:**
- `lib/auth0.ts` - Auth0 client instance with lazy initialization
- `components/AuthProvider.tsx` - App-wide Auth0 provider
- `app/api/auth/[...auth0]/route.ts` - Auth0 callback handler

### Session Management

**Auth0 Session:**
- Access tokens stored in secure HTTP-only cookies
- Refresh tokens managed by SDK
- Session persists across page reloads

**API Authentication:**
- Server components: Use `auth0.getAccessToken()` to fetch token
- Client components: Proxy `/api/proxy/` automatically injects token

### Login Flow

1. User clicks login → Redirects to Auth0
2. Auth0 authenticates → Redirects to `/auth/callback`
3. SDK processes callback → Sets session cookies
4. User redirected to home page

### Logout Flow

1. User clicks logout → Calls `auth0.logout()`
2. Redirects to Auth0 logout endpoint
3. Clears session cookies
4. Redirects to home page

---

## API Integration

### Server-Side Fetching

Use `fetchServer()` in Server Components:

```tsx
import { fetchServer } from '@/lib/server';

export default async function Page() {
  const res = await fetchServer('/api/equipment');
  const data = await res.json();

  return <div>{/* render */}</div>;
}
```

**Features:**
- Automatically includes Auth0 access token
- 10-second timeout
- Configurable via `API_URL` env var

### Client-Side Fetching

Use `fetchClient()` in Client Components:

```tsx
'use client';
import { fetchClient } from '@/lib/api';
import { useState } from 'react';

export default function Component() {
  const [data, setData] = useState(null);

  useEffect(() => {
    fetchClient('/api/equipment').then(res => res.json()).then(setData);
  }, []);

  return <div>{/* render */}</div>;
}
```

**Features:**
- Proxies through `/api/proxy/[...path]/`
- Automatically injects Auth0 token
- 15-second timeout

### API Proxy Route

`app/api/proxy/[...path]/route.ts` handles all backend calls:

- Validates path segments (prevents directory traversal)
- Fetches Auth0 access token
- Forwards request to backend API
- Returns backend response

---

## Components

### shadcn/ui Components

Located in `components/ui/` - styled, accessible components:

- Button, Card, Input, Textarea
- Form, FormField, FormItem, FormLabel, FormMessage
- Select, Checkbox, RadioGroup
- Dialog, DropdownMenu, Sheet
- Table, Avatar, Badge
- Tabs, Accordion, Separator
- Toast/Sonner, Alert

**Adding new shadcn/ui components:**
```bash
npx shadcn@latest add <component-name>
```

### Custom Components

**Navbar** (`components/Navbar.tsx`)
- Navigation menu
- User menu with profile, logout
- Admin link (shows for admin role)
- Theme toggle

**Footer** (`components/Footer.tsx`)
- Footer links
- Copyright info

**AuthProvider** (`components/AuthProvider.tsx`)
- Wraps app with Auth0 provider
- Handles authentication context

**ThemeProvider** (`components/theme-provider.tsx`)
- Dark/light theme management
- System theme detection

---

## Custom Hooks

### useChatWebSocket

Real-time messaging hook for WebSocket connections:

```tsx
import { useChatWebSocket } from '@/hooks/useChatWebSocket';

export default function ChatComponent({ conversationId }: { conversationId: string }) {
  const { messages, isConnected, sendMessage } = useChatWebSocket(conversationId);

  return (
    <div>
      {messages.map(msg => <div key={msg.id}>{msg.content}</div>)}
      <button onClick={() => sendMessage('Hello')}>Send</button>
    </div>
  );
}
```

**Features:**
- Automatic connection management
- Message deduplication
- Connection status tracking
- Auto-reconnection on disconnect

---

## Forms & Validation

### React Hook Form + Zod Pattern

```tsx
'use client';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import * as z from 'zod';
import { Form, FormField, FormItem, FormLabel, FormControl } from '@/components/ui/form';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';

const schema = z.object({
  title: z.string().min(3, 'Title must be at least 3 characters').max(200),
  description: z.string().min(10, 'Description must be at least 10 characters'),
});

export default function MyForm() {
  const form = useForm({
    resolver: zodResolver(schema),
    defaultValues: { title: '', description: '' },
  });

  const onSubmit = async (data: z.infer<typeof schema>) => {
    await fetchClient('/api/equipment', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  };

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(onSubmit)}>
        <FormField name="title" render={({ field }) => (
          <FormItem>
            <FormLabel>Title</FormLabel>
            <FormControl><Input {...field} /></FormControl>
          </FormItem>
        )} />
        <Button type="submit">Submit</Button>
      </form>
    </Form>
  );
}
```

---

## Server Actions

Used for form submissions that need server-side execution:

**Profile Actions** (`actions/profile/actions.ts`):
```ts
'use server';

import { revalidatePath } from 'next/cache';
import { fetchServer } from '@/lib/server';

export async function updateProfile(formData: FormData) {
  const username = formData.get('username') as string;
  const res = await fetchServer(`/api/users/${userId}`, {
    method: 'PUT',
    body: JSON.stringify({ username }),
  });

  revalidatePath('/profile');
  return res.ok;
}
```

---

## Styling

### Tailwind CSS

Configuration in `tailwind.config.ts`:
- Custom theme via CSS variables
- Dark mode support via `class` strategy
- Custom colors, spacing, border radius

### CSS Variables

Defined in `app/globals.css`:
- `--background`, `--foreground`
- `--card`, `--card-foreground`
- `--popover`, `--popover-foreground`
- `--primary`, `--primary-foreground`
- `--secondary`, `--secondary-foreground`
- `--muted`, `--muted-foreground`
- `--accent`, `--accent-foreground`
- `--destructive`, `--destructive-foreground`
- `--border`, `--input`, `--ring`

### Dark Mode

Controlled by `next-themes`:
- System default detection
- Manual toggle in Navbar
- Persists in localStorage
- Applies `dark` class to `html` element

---

## State Management

### Patterns Used

1. **Server Components** - Data fetched at request time, no hydration
2. **Client State** - React hooks for component state
3. **Server Actions** - Mutations with cache revalidation
4. **WebSocket** - Real-time updates for messages

### No Global State Library

The app intentionally avoids Redux/Zustand:
- Use URL params for filtering
- Use React hooks for component state
- Use Server Components for data fetching

---

## Error Handling

### API Errors

Display errors using `sonner` toast notifications:

```tsx
import { toast } from 'sonner';

const res = await fetchClient('/api/equipment', {
  method: 'POST',
  body: JSON.stringify(data),
});

if (!res.ok) {
  const error = await res.json();
  toast.error(error.message || 'Something went wrong');
}
```

### Not Found

Next.js default 404 page handles missing routes.

### Unauthorized

Redirect to login for protected routes.

---

## Deployment

### Environment Variables

Create `.env.local` in frontend directory:

```bash
# Auth0 Configuration
AUTH0_BASE_URL=http://localhost:3000  # or your production URL
AUTH0_DOMAIN=your-tenant.us.auth0.com
AUTH0_CLIENT_ID=your-client-id
AUTH0_SECRET=your-session-secret (32+ random chars)
AUTH0_AUDIENCE=your-api-audience

# Backend API
API_URL=http://localhost:8080  # or your production API URL
```

### Build Process

```bash
npm run build
```

**Output Configuration (next.config.ts):**
- Standalone output for containerization
- No TypeScript errors at build time

### Docker

Frontend Dockerfile uses multi-stage build:
- Base: Node.js Alpine
- Build: Install dependencies and build
- Production: Copy build artifacts only

---

## Development

### Scripts

| Command | Description |
|----------|-------------|
| `npm run dev` | Start development server on port 3000 |
| `npm run build` | Build for production |
| `npm start` | Start production server |
| `npm run lint` | Run ESLint |

### Adding a New Page

1. Create `src/app/{route}/page.tsx`
2. Import `fetchServer` or `fetchClient`
3. Fetch data and render
4. Add navigation link in Navbar if needed

### Adding a New Component

1. Create `src/components/ComponentName.tsx`
2. Add shadcn/ui components via `npx shadcn@latest add` if needed
3. Export component
4. Import and use in pages

---

## Common Patterns

### Protected Route Pattern

```tsx
import { redirect } from 'next/navigation';
import { auth0 } from '@/lib/auth0';
import { fetchServer } from '@/lib/server';

export default async function ProtectedPage() {
  const session = await auth0.getSession();

  if (!session) {
    redirect('/auth/login');
  }

  const user = await fetchServer('/api/auth/me');
  // ... render page
}
```

### Admin Guard Pattern

```tsx
import { requireAdmin } from '@/lib/adminGuard';

export default async function AdminPage() {
  const adminUser = await requireAdmin();

  // user.role is guaranteed to be 'admin'
  // ... render admin page
}
```

### Loading State Pattern

```tsx
'use client';
import { useState } from 'react';

export default function DataComponent() {
  const [loading, setLoading] = useState(true);
  const [data, setData] = useState(null);

  useEffect(() => {
    fetchData().then(data => {
      setData(data);
      setLoading(false);
    });
  }, []);

  if (loading) return <div>Loading...</div>;
  return <div>{/* render data */}</div>;
}
```

---

## Troubleshooting

### "Auth0 callback failed"

- Check `AUTH0_BASE_URL` matches Auth0 application settings
- Verify callback URLs in Auth0 dashboard
- Check frontend and backend `AUTH0_DOMAIN` are same

### "API request unauthorized"

- Ensure user is logged in
- Check `API_URL` environment variable
- Verify backend is running
- Check console for token errors

### "WebSocket not connecting"

- Verify user is authenticated
- Check WebSocket URL in browser console
- Ensure backend WebSocket endpoint is accessible
- Check token is included in query parameter

### "Theme not persisting"

- Check localStorage for theme preference
- Ensure `ThemeProvider` wraps app
- Check browser's theme preference setting

---

## Key Files Reference

| Purpose | Location |
|---------|----------|
| Root layout | `src/app/layout.tsx` |
| Home page | `src/app/page.tsx` |
| API client | `src/lib/api.ts` |
| Server fetch | `src/lib/server.ts` |
| Auth0 config | `src/lib/auth0.ts` |
| Admin guard | `src/lib/adminGuard.ts` |
| WebSocket hook | `src/hooks/useChatWebSocket.ts` |
| Next.js config | `next.config.ts` |
| Tailwind config | `tailwind.config.ts` |
| TypeScript config | `tsconfig.json` |
