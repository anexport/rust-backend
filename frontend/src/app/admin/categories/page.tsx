'use client';

import { FormEvent, useCallback, useEffect, useState } from 'react';
import { toast } from 'sonner';
import { fetchClient } from '@/lib/api';
import { DataTable } from '@/components/admin/DataTable';
import { ConfirmDialog } from '@/components/admin/ConfirmDialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';

type Category = {
  id: string;
  name: string;
  parent_id?: string | null;
};

export default function AdminCategoriesPage() {
  const [categories, setCategories] = useState<Category[]>([]);
  const [name, setName] = useState('');
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editingName, setEditingName] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  const load = useCallback(async () => {
    try {
      const res = await fetchClient('/api/admin/categories', { cache: 'no-store' });
      if (!res.ok) {
        toast.error('Failed to load categories');
        return;
      }
      setCategories((await res.json()) as Category[]);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      toast.error(`Failed to load categories: ${message}`);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const createCategory = async (event: FormEvent) => {
    event.preventDefault();
    if (!name.trim() || isSubmitting) {
      return;
    }

    setIsSubmitting(true);
    try {
      const res = await fetchClient('/api/admin/categories', {
        method: 'POST',
        body: JSON.stringify({ name: name.trim() }),
      });

      if (!res.ok) {
        toast.error('Unable to create category');
        return;
      }

      setName('');
      toast.success('Category created');
      await load();
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      toast.error(`Unable to create category: ${message}`);
    } finally {
      setIsSubmitting(false);
    }
  };

  const updateCategory = async (id: string) => {
    if (isSubmitting) {
      return;
    }
    if (!editingName.trim()) {
      toast.error('Name is required');
      return;
    }

    setIsSubmitting(true);
    try {
      const res = await fetchClient(`/api/admin/categories/${id}`, {
        method: 'PUT',
        body: JSON.stringify({ name: editingName.trim() }),
      });
      if (!res.ok) {
        toast.error('Unable to update category');
        return;
      }
      setEditingId(null);
      setEditingName('');
      toast.success('Category updated');
      await load();
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      toast.error(`Unable to update category: ${message}`);
    } finally {
      setIsSubmitting(false);
    }
  };

  const deleteCategory = async (id: string) => {
    if (isSubmitting || editingId !== null) {
      return;
    }

    setIsSubmitting(true);
    try {
      const res = await fetchClient(`/api/admin/categories/${id}`, { method: 'DELETE' });
      if (!res.ok) {
        toast.error('Unable to delete category');
        return;
      }
      toast.success('Category deleted');
      await load();
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      toast.error(`Unable to delete category: ${message}`);
    } finally {
      setIsSubmitting(false);
    }
  };

  const categoryNameById = new Map(categories.map((category) => [category.id, category.name]));

  const rows = categories.map((category) => [
    editingId === category.id ? (
      <div key={`${category.id}-edit`} className="flex items-center gap-2">
        <Input value={editingName} onChange={(e) => setEditingName(e.target.value)} disabled={isSubmitting} />
        <Button size="sm" onClick={() => void updateCategory(category.id)} disabled={isSubmitting}>
          {isSubmitting ? 'Saving...' : 'Save'}
        </Button>
        <Button
          variant="outline"
          size="sm"
          onClick={() => {
            setEditingId(null);
            setEditingName('');
          }}
          disabled={isSubmitting}
        >
          Cancel
        </Button>
      </div>
    ) : (
      category.name
    ),
    category.parent_id ? categoryNameById.get(category.parent_id) || '-' : '-',
    <div key={`${category.id}-actions`} className="flex items-center gap-2">
      <Button
        variant="outline"
        size="sm"
        onClick={() => {
          setEditingId(category.id);
          setEditingName(category.name);
        }}
        disabled={isSubmitting || (editingId !== null && editingId !== category.id)}
      >
        Edit
      </Button>
      <ConfirmDialog
        title="Delete category"
        description={`Delete ${category.name}?`}
        triggerLabel="Delete"
        confirmLabel="Delete"
        onConfirm={() => deleteCategory(category.id)}
        disabled={isSubmitting || editingId !== null}
      />
    </div>,
  ]);

  return (
    <div className="space-y-4">
      <form className="flex max-w-lg items-center gap-2" onSubmit={createCategory}>
        <Input
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="New category name"
          disabled={isSubmitting}
        />
        <Button type="submit" disabled={isSubmitting}>
          {isSubmitting ? 'Adding...' : 'Add Category'}
        </Button>
      </form>

      <DataTable headers={['Name', 'Parent', 'Actions']} rows={rows} emptyLabel="No categories found" />
    </div>
  );
}
