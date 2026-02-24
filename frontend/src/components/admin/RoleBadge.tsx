import { cn } from '@/lib/utils';

const styleByRole: Record<string, string> = {
  admin: 'bg-red-100 text-red-800 border-red-200',
  owner: 'bg-blue-100 text-blue-800 border-blue-200',
  renter: 'bg-zinc-100 text-zinc-700 border-zinc-200',
};

type RoleBadgeProps = {
  role: string;
};

export function RoleBadge({ role }: RoleBadgeProps) {
  const normalized = role.toLowerCase();
  return (
    <span
      aria-label={`Role: ${normalized}`}
      className={cn(
        'inline-flex rounded-full border px-2 py-0.5 text-xs font-medium',
        styleByRole[normalized] ?? styleByRole.renter,
      )}
    >
      {normalized}
    </span>
  );
}
