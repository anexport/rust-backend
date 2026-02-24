'use client';

import { useCallback, useEffect, useState } from 'react';
import { toast } from 'sonner';
import { Copy } from 'lucide-react';
import { fetchClient } from '@/lib/api';
import { DataTable } from '@/components/admin/DataTable';
import { SearchInput } from '@/components/admin/SearchInput';
import { RoleBadge } from '@/components/admin/RoleBadge';
import { ConfirmDialog } from '@/components/admin/ConfirmDialog';
import { Button } from '@/components/ui/button';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';

type UserRow = {
  id: string;
  email: string;
  role: string;
  username?: string | null;
  full_name?: string | null;
  created_at: string;
  equipment_count: number;
};

type UsersResponse = {
  users: UserRow[];
  total: number;
  page: number;
  per_page: number;
};

export default function AdminUsersPage() {
  const [data, setData] = useState<UsersResponse>({ users: [], total: 0, page: 1, per_page: 25 });
  const [page, setPage] = useState(1);
  const [perPage, setPerPage] = useState(25);
  const [search, setSearch] = useState('');
  const [roleFilter, setRoleFilter] = useState('all');

  const load = useCallback(async () => {
    try {
      const query = new URLSearchParams({ page: String(page), per_page: String(perPage), search });
      if (roleFilter !== 'all') {
        query.set('role', roleFilter);
      }

      const res = await fetchClient(`/api/admin/users?${query.toString()}`, { cache: 'no-store' });
      if (!res.ok) {
        toast.error('Failed to load users');
        return;
      }
      setData((await res.json()) as UsersResponse);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      toast.error(`Failed to load users: ${message}`);
    }
  }, [page, perPage, search, roleFilter]);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    const nextTotalPages = Math.max(1, Math.ceil(data.total / perPage));
    if (page > nextTotalPages) {
      setPage(nextTotalPages);
    }
  }, [data.total, page, perPage]);

  const updateRole = async (id: string, role: string) => {
    try {
      const res = await fetchClient(`/api/admin/users/${id}/role`, {
        method: 'PUT',
        body: JSON.stringify({ role }),
      });
      if (!res.ok) {
        toast.error('Unable to update role');
        return;
      }
      toast.success('Role updated');
      void load();
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      toast.error(`Unable to update role: ${message}`);
    }
  };

  const deleteUser = async (id: string) => {
    try {
      const res = await fetchClient(`/api/admin/users/${id}`, { method: 'DELETE' });
      if (!res.ok) {
        toast.error('Unable to delete user');
        return;
      }
      toast.success('User deleted');
      void load();
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      toast.error(`Unable to delete user: ${message}`);
    }
  };

  const rows = data.users.map((user) => [
    user.email,
    <RoleBadge key={`${user.id}-badge`} role={user.role} />,
    user.username || '-',
    String(user.equipment_count),
    <div key={`${user.id}-actions`} className="flex items-center gap-2">
      <Select
        value={user.role}
        onValueChange={(value) => {
          if (value === 'admin' && user.role !== 'admin') {
            if (!window.confirm(`Promote ${user.email} to admin?`)) {
              return;
            }
          }
          void updateRole(user.id, value);
        }}
      >
        <SelectTrigger size="sm">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="renter">renter</SelectItem>
          <SelectItem value="owner">owner</SelectItem>
          <SelectItem value="admin">admin</SelectItem>
        </SelectContent>
      </Select>
      <Button
        variant="outline"
        size="sm"
        onClick={() => {
          void navigator.clipboard
            .writeText(user.id)
            .then(() => {
              toast.success('User id copied');
            })
            .catch((error) => {
              const message = error instanceof Error ? error.message : 'Unknown error';
              toast.error(`Unable to copy user id: ${message}`);
            });
        }}
      >
        <Copy className="h-3 w-3" />
      </Button>
      <ConfirmDialog
        title="Delete user"
        description={`Delete ${user.email}? This action cannot be undone.`}
        triggerLabel="Delete"
        confirmLabel="Delete"
        onConfirm={() => deleteUser(user.id)}
      />
    </div>,
  ]);

  const totalPages = Math.max(1, Math.ceil(data.total / perPage));

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <SearchInput
          value={search}
          onSearch={(value) => {
            setPage(1);
            setSearch(value);
          }}
          placeholder="Search email or username"
        />
        <Select
          value={roleFilter}
          onValueChange={(value) => {
            setPage(1);
            setRoleFilter(value);
          }}
        >
          <SelectTrigger>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All roles</SelectItem>
            <SelectItem value="renter">Renter</SelectItem>
            <SelectItem value="owner">Owner</SelectItem>
            <SelectItem value="admin">Admin</SelectItem>
          </SelectContent>
        </Select>
      </div>

      <DataTable
        headers={['Email', 'Role', 'Username', 'Equipment', 'Actions']}
        rows={rows}
        emptyLabel="No users found"
      />

      <div className="flex items-center gap-2">
        <Button variant="outline" onClick={() => setPage((p) => Math.max(1, p - 1))}>
          Previous
        </Button>
        <span className="text-sm">Page {page} of {totalPages}</span>
        <Button variant="outline" onClick={() => setPage((p) => Math.min(totalPages, p + 1))}>
          Next
        </Button>
        <Select
          value={String(perPage)}
          onValueChange={(value) => {
            setPage(1);
            setPerPage(Number(value));
          }}
        >
          <SelectTrigger>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="10">10 / page</SelectItem>
            <SelectItem value="25">25 / page</SelectItem>
            <SelectItem value="50">50 / page</SelectItem>
          </SelectContent>
        </Select>
      </div>
    </div>
  );
}
