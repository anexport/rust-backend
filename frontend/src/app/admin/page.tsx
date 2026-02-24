import { Users, Wrench, PackageCheck, Tags } from 'lucide-react';
import Link from 'next/link';
import { fetchServer } from '@/lib/server';
import { StatCard } from '@/components/admin/StatCard';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

export const dynamic = 'force-dynamic';

type Stats = {
  total_users: number;
  total_equipment: number;
  available_equipment: number;
  total_categories: number;
};

type AdminUsersResponse = {
  users: Array<{ id: string; email: string; role: string; created_at: string }>;
};

type AdminEquipmentResponse = {
  equipment: Array<{ id: string; title: string; owner_email: string; created_at: string }>;
};

export default async function AdminOverviewPage() {
  let statsRes: Response;
  let usersRes: Response;
  let equipmentRes: Response;

  try {
    [statsRes, usersRes, equipmentRes] = await Promise.all([
      fetchServer('/api/admin/stats', { cache: 'no-store' }),
      fetchServer('/api/admin/users?per_page=5&page=1', { cache: 'no-store' }),
      fetchServer('/api/admin/equipment?per_page=5&page=1', { cache: 'no-store' }),
    ]);
  } catch (error) {
    console.error('Failed to load admin overview', error);
    const fallback = new Response(null, { status: 500 });
    statsRes = fallback;
    usersRes = fallback;
    equipmentRes = fallback;
  }

  const stats: Stats = statsRes.ok
    ? await statsRes.json()
    : { total_users: 0, total_equipment: 0, available_equipment: 0, total_categories: 0 };
  const users: AdminUsersResponse = usersRes.ok ? await usersRes.json() : { users: [] };
  const equipment: AdminEquipmentResponse = equipmentRes.ok ? await equipmentRes.json() : { equipment: [] };

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard title="Total Users" value={stats.total_users} icon={<Users className="h-4 w-4" />} />
        <StatCard title="Total Equipment" value={stats.total_equipment} icon={<Wrench className="h-4 w-4" />} />
        <StatCard title="Available" value={stats.available_equipment} icon={<PackageCheck className="h-4 w-4" />} />
        <StatCard title="Categories" value={stats.total_categories} icon={<Tags className="h-4 w-4" />} />
      </div>

      <div className="flex gap-2">
        <Link href="/admin/categories" className="rounded-md bg-primary px-4 py-2 text-sm text-primary-foreground">
          Add Category
        </Link>
        <Link href="/admin/users" className="rounded-md border px-4 py-2 text-sm">
          View All Users
        </Link>
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Recent Users</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-sm">
            {users.users.map((user) => (
              <div key={user.id} className="flex items-center justify-between gap-4 rounded border px-3 py-2">
                <span className="truncate" title={user.email}>{user.email}</span>
                <span className="shrink-0 text-muted-foreground">{user.role}</span>
              </div>
            ))}
            {users.users.length === 0 ? <p className="text-muted-foreground">No users found.</p> : null}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Recent Equipment</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-sm">
            {equipment.equipment.map((item) => (
              <div key={item.id} className="flex items-center justify-between gap-4 rounded border px-3 py-2">
                <span className="truncate" title={item.title}>{item.title}</span>
                <span className="shrink-0 text-muted-foreground truncate max-w-[150px]" title={item.owner_email}>
                  {item.owner_email}
                </span>
              </div>
            ))}
            {equipment.equipment.length === 0 ? <p className="text-muted-foreground">No equipment found.</p> : null}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
