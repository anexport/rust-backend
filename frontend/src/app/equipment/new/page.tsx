'use client';

import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import * as z from 'zod';
import { Button } from '@/components/ui/button';
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from '@/components/ui/form';
import { Input } from '@/components/ui/input';
import { fetchClient } from '@/lib/api';
import { toast } from 'sonner';
import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';

const newEquipmentSchema = z.object({
  title: z.string().min(3).max(200),
  description: z.string().min(10),
  daily_rate: z.string().min(1, 'Daily rate is required'),
  condition: z.string().min(1),
  location: z.string().min(2).max(255),
  category_id: z.string().uuid(),
});

type FormValues = z.infer<typeof newEquipmentSchema>;

export default function NewEquipmentPage() {
  const [isLoading, setIsLoading] = useState(false);
  const [categories, setCategories] = useState<{id: string, name: string}[]>([]);
  const router = useRouter();

  useEffect(() => {
    fetchClient('/api/categories')
      .then(res => res.json())
      .then(data => setCategories(data))
      .catch(() => toast.error('Failed to load categories'));
  }, []);

  const form = useForm<FormValues>({
    resolver: zodResolver(newEquipmentSchema),
    defaultValues: {
      title: '',
      description: '',
      daily_rate: '',
      condition: 'good',
      location: '',
      category_id: '',
    },
  });

  async function onSubmit(data: FormValues) {
    setIsLoading(true);
    
    const payload = {
       ...data,
       daily_rate: data.daily_rate
    };

    const res = await fetchClient('/api/equipment', {
      method: 'POST',
      body: JSON.stringify(payload),
    });

    setIsLoading(false);

    if (!res.ok) {
      toast.error('Failed to create listing');
    } else {
      const item = await res.json();
      toast.success('Listing created successfully!');
      router.push(`/equipment/${item.id}`);
      router.refresh();
    }
  }

  return (
    <main className="container mx-auto py-10 px-4 max-w-2xl">
      <h1 className="text-3xl font-bold mb-6">List Equipment</h1>
      
      <Form {...form}>
        <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
          <FormField
            control={form.control}
            name="title"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Title</FormLabel>
                <FormControl>
                  <Input placeholder="DeWalt Drill" {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
          
          <FormField
            control={form.control}
            name="category_id"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Category</FormLabel>
                <FormControl>
                  <select 
                    className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
                    {...field}
                  >
                    <option value="" disabled>Select a category</option>
                    {categories.map(c => (
                      <option key={c.id} value={c.id}>{c.name}</option>
                    ))}
                  </select>
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name="description"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Description</FormLabel>
                <FormControl>
                  <textarea 
                    className="flex min-h-[80px] w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
                    placeholder="Details about the item..." 
                    {...field} 
                  />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          <div className="grid grid-cols-2 gap-4">
            <FormField
              control={form.control}
              name="daily_rate"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Daily Rate ($)</FormLabel>
                  <FormControl>
                    <Input type="number" step="0.01" {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            
            <FormField
              control={form.control}
              name="condition"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Condition</FormLabel>
                  <FormControl>
                    <Input placeholder="excellent, good, fair" {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
          </div>

          <FormField
            control={form.control}
            name="location"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Location</FormLabel>
                <FormControl>
                  <Input placeholder="City, State or Zip" {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          <Button type="submit" disabled={isLoading} className="w-full">
            {isLoading ? 'Creating...' : 'Create Listing'}
          </Button>
        </form>
      </Form>
    </main>
  );
}
