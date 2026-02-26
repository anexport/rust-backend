import type { ReactNode } from 'react';
import Link from 'next/link';
import { ShieldCheck, LayoutDashboard, Users, Wrench, Tags } from 'lucide-react';
import { requireAdmin } from '@/lib/adminGuard';
import { Tooltip, TooltipContent, TooltipTrigger, TooltipProvider } from '@/components/ui/tooltip';

export const dynamic = 'force-dynamic';

const navItems = [
  { href: '/admin', label: 'Overview', icon: LayoutDashboard },
  { href: '/admin/users', label: 'Users', icon: Users },
  { href: '/admin/equipment', label: 'Equipment', icon: Wrench },
  { href: '/admin/categories', label: 'Categories', icon: Tags },
];

export default async function AdminLayout({ children }: { children: ReactNode }) {
  const user = await requireAdmin();

  return (
    <main className="container mx-auto px-4 md:px-6 py-8 max-w-7xl">
      <div className="grid grid-cols-1 gap-6 md:grid-cols-[220px_1fr]">
        <aside className="rounded-lg border p-3">
          <div className="mb-4 flex items-center gap-2 px-2 text-sm font-semibold">
            <ShieldCheck className="h-4 w-4" />
            Admin Panel
          </div>
          <nav className="space-y-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  className="hover:bg-accent flex items-center gap-2 rounded-md px-2 py-2 text-sm"
                >
                  <Icon className="h-4 w-4" />
                  {item.label}
                </Link>
              );
            })}
          </nav>
          <div className="text-muted-foreground mt-4 border-t px-2 pt-3 text-xs">
            <TooltipProvider delayDuration={0}>
              <div className="flex flex-col gap-0.5 overflow-hidden">
                <span className="shrink-0">Signed in as:</span>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <button
                      type="button"
                      className="truncate font-medium cursor-help text-left bg-transparent border-0 p-0 text-inherit text-xs"
                      tabIndex={0}
                    >
                      {user.email ?? 'unknown'}
                    </button>
                  </TooltipTrigger>
                  <TooltipContent side="top" className="max-w-none">
                    <p>{user.email ?? 'unknown'}</p>
                  </TooltipContent>
                </Tooltip>
              </div>
            </TooltipProvider>
          </div>
        </aside>
        <section>
          <div className="mb-4 flex justify-end">
            <span className="inline-flex rounded-full border border-red-200 bg-red-50 px-2 py-1 text-xs font-medium text-red-700">
              Admin
            </span>
          </div>
          {children}
        </section>
      </div>
    </main>
  );
}
