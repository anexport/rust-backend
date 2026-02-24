'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import { toast } from 'sonner';
import { fetchClient } from '@/lib/api';
import { DataTable } from '@/components/admin/DataTable';
import { SearchInput } from '@/components/admin/SearchInput';
import { ConfirmDialog } from '@/components/admin/ConfirmDialog';
import { Button } from '@/components/ui/button';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';

type EquipmentRow = {
  id: string;
  title: string;
  owner_email: string;
  category_name: string;
  daily_rate: number;
  is_available: boolean;
};

type EquipmentResponse = {
  equipment: EquipmentRow[];
  total: number;
  page: number;
  per_page: number;
};

export default function AdminEquipmentPage() {
  const [data, setData] = useState<EquipmentResponse>({ equipment: [], total: 0, page: 1, per_page: 20 });
  const [page, setPage] = useState(1);
  const [perPage, setPerPage] = useState(20);
  const [search, setSearch] = useState('');

  const load = useCallback(async () => {
    try {
      const query = new URLSearchParams({ page: String(page), per_page: String(perPage), search });
      const res = await fetchClient(`/api/admin/equipment?${query.toString()}`, { cache: 'no-store' });
      if (!res.ok) {
        toast.error('Failed to load equipment');
        return;
      }
      setData((await res.json()) as EquipmentResponse);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      toast.error(`Failed to load equipment: ${message}`);
    }
  }, [page, perPage, search]);

  useEffect(() => {
    void load();
  }, [load]);

  const toggleAvailability = useCallback(
    async (id: string, current: boolean) => {
      try {
        const res = await fetchClient(`/api/admin/equipment/${id}/availability`, {
          method: 'PUT',
          body: JSON.stringify({ is_available: !current }),
        });
        if (!res.ok) {
          toast.error('Unable to update availability');
          return;
        }
        toast.success('Availability updated');
        void load();
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Unknown error';
        toast.error(`Unable to update availability: ${message}`);
      }
    },
    [load],
  );

  const deleteEquipment = useCallback(
    async (id: string) => {
      try {
        const res = await fetchClient(`/api/admin/equipment/${id}`, { method: 'DELETE' });
        if (!res.ok) {
          toast.error('Unable to delete equipment');
          return;
        }
        toast.success('Equipment deleted');
        void load();
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Unknown error';
        toast.error(`Unable to delete equipment: ${message}`);
      }
    },
    [load],
  );

  const rows = useMemo(
    () =>
      data.equipment.map((item) => [
        item.title,
        item.owner_email,
        item.category_name,
        `$${item.daily_rate}`,
        item.is_available ? 'Available' : 'Unavailable',
        <div key={`${item.id}-actions`} className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => void toggleAvailability(item.id, item.is_available)}>
            Toggle
          </Button>
          <ConfirmDialog
            title="Delete equipment"
            description={`Delete ${item.title}? This action cannot be undone.`}
            triggerLabel="Delete"
            confirmLabel="Delete"
            onConfirm={() => {
              void deleteEquipment(item.id);
            }}
          />
        </div>,
      ]),
    [data.equipment, toggleAvailability, deleteEquipment],
  );

  const totalPages = Math.max(1, Math.ceil(data.total / perPage));

  return (
    <div className="space-y-4">
      <SearchInput value={search} onSearch={(value) => { setPage(1); setSearch(value); }} placeholder="Search title or owner" />

      <DataTable
        headers={['Title', 'Owner', 'Category', 'Rate', 'Availability', 'Actions']}
        rows={rows}
        emptyLabel="No equipment found"
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
