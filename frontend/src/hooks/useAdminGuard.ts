'use client';

import { useEffect, useRef, useState } from 'react';
import { useRouter } from 'next/navigation';
import { toast } from 'sonner';
import { fetchClient } from '@/lib/api';

type AuthMeResponse = {
  id: string;
  email: string;
  role: string;
  username?: string | null;
  full_name?: string | null;
  avatar_url?: string | null;
};

export function useAdminGuard() {
  const router = useRouter();
  const routerRef = useRef(router);
  const [isLoading, setIsLoading] = useState(true);
  const [isAdmin, setIsAdmin] = useState(false);
  const [user, setUser] = useState<AuthMeResponse | null>(null);

  useEffect(() => {
    let mounted = true;

    const run = async () => {
      try {
        const res = await fetchClient('/api/auth/me', { cache: 'no-store' });
        if (!mounted) {
          return;
        }

        if (res.status === 401) {
          toast.error('Please log in to access admin pages.');
          routerRef.current.replace('/');
          return;
        }

        const data = (await res.json()) as AuthMeResponse;
        const hasAdminRole = data.role === 'admin';
        setUser(data);
        setIsAdmin(hasAdminRole);

        if (!hasAdminRole) {
          toast.error('Admin access is required.');
          routerRef.current.replace('/');
        }
      } catch {
        if (mounted) {
          toast.error('Unable to verify admin access.');
          routerRef.current.replace('/');
        }
      } finally {
        if (mounted) {
          setIsLoading(false);
        }
      }
    };

    void run();

    return () => {
      mounted = false;
    };
  }, []);

  return { isLoading, isAdmin, user };
}
