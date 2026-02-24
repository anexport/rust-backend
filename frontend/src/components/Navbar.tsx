'use client';

import Link from 'next/link';
import { useEffect, useState } from 'react';
import { useUser } from '@auth0/nextjs-auth0';
import { ShieldCheck, Plus } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { fetchClient } from '@/lib/api';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { ModeToggle } from '@/components/theme-toggle';

export function Navbar() {
  const { user, isLoading } = useUser();
  const [role, setRole] = useState<string | null>(null);

  useEffect(() => {
    let mounted = true;
    const loadRole = async () => {
      if (!user) {
        setRole(null);
        return;
      }
      try {
        const res = await fetchClient('/api/auth/me', { cache: 'no-store' });
        if (!mounted || !res.ok) {
          setRole(null);
          return;
        }
        const body = (await res.json()) as { role?: string };
        setRole(body.role ?? null);
      } catch {
        if (mounted) {
          setRole(null);
        }
      }
    };

    void loadRole();
    return () => {
      mounted = false;
    };
  }, [user]);

  return (
    <header className="sticky top-0 z-50 w-full border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
      <div className="container mx-auto flex h-14 items-center px-4 md:px-6 max-w-7xl">
        <Link href="/" className="mr-6 flex items-center space-x-2 font-bold">
          <span>Rust Backend UI</span>
        </Link>
        <nav className="flex flex-1 items-center space-x-6 text-sm font-medium">
          <Link href="/equipment" className="transition-colors hover:text-foreground/80">
            Equipment
          </Link>
          <Link href="/messages" className="transition-colors hover:text-foreground/80">
            Messages
          </Link>
          {role === 'admin' ? (
            <Link href="/admin" className="flex items-center gap-1 transition-colors hover:text-foreground/80">
              <ShieldCheck className="h-4 w-4" />
              Admin
            </Link>
          ) : null}
        </nav>
        <div className="flex items-center justify-end space-x-4">
          <ModeToggle />
          {!isLoading && (
            <>
              {user ? (
                <div className="flex items-center space-x-4">
                  <Button asChild variant="outline" size="sm" className="hidden sm:flex">
                    <Link href="/equipment/new">
                      <Plus className="mr-2 h-4 w-4" />
                      List Gear
                    </Link>
                  </Button>
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button variant="ghost" className="relative h-8 w-8 rounded-full">
                        <Avatar className="h-8 w-8">
                          <AvatarImage src={user.picture || ''} alt={user.name || ''} />
                          <AvatarFallback>{user.name?.charAt(0) || 'U'}</AvatarFallback>
                        </Avatar>
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end">
                      <DropdownMenuItem asChild>
                        <Link href="/profile">Profile</Link>
                      </DropdownMenuItem>
                      <DropdownMenuItem asChild>
                        <Link href="/equipment/new" className="sm:hidden">List Gear</Link>
                      </DropdownMenuItem>
                      <DropdownMenuItem asChild>
                        <a href="/auth/logout">Log out</a>
                      </DropdownMenuItem>
                    </DropdownMenuContent>
                  </DropdownMenu>
                </div>
              ) : (
                <Button asChild>
                  <a href="/auth/login">Log In</a>
                </Button>
              )}
            </>
          )}
        </div>
      </div>
    </header>
  );
}
