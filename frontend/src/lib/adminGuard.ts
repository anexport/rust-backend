import { redirect } from 'next/navigation';
import * as z from 'zod';
import { fetchServer } from '@/lib/api';

export type AdminUser = {
  id: string;
  email: string;
  role: string;
  username?: string | null;
  full_name?: string | null;
  avatar_url?: string | null;
};

const adminUserSchema = z.object({
  id: z.string(),
  email: z.string(),
  role: z.string(),
  username: z.string().nullable().optional(),
  full_name: z.string().nullable().optional(),
  avatar_url: z.string().nullable().optional(),
});

export async function requireAdmin(): Promise<AdminUser> {
  const res = await fetchServer('/api/auth/me', { cache: 'no-store' });

  if (res.status === 401) {
    redirect('/');
  }

  if (!res.ok) {
    redirect('/');
  }

  let body: unknown;
  try {
    body = await res.json();
  } catch {
    redirect('/');
  }

  const parsed = adminUserSchema.safeParse(body);
  if (!parsed.success) {
    redirect('/');
  }

  const user = parsed.data;
  if (user.role !== 'admin') {
    redirect('/');
  }

  return user;
}
