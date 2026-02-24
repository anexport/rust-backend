'use client';

import type { ReactNode } from 'react';
import { Auth0Provider } from '@auth0/nextjs-auth0';

export default function AuthProvider({ children }: { children: ReactNode }) {
  return <Auth0Provider>{children}</Auth0Provider>;
}
