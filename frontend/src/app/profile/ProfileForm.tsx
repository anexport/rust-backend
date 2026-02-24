'use client';

import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import * as z from 'zod';
import { Button } from '@/components/ui/button';
import { Form, FormControl, FormDescription, FormField, FormItem, FormLabel, FormMessage } from '@/components/ui/form';
import { Input } from '@/components/ui/input';
import { updateProfile } from './actions';
import { toast } from 'sonner';
import { useState } from 'react';

const profileFormSchema = z.object({
  username: z.string().min(3, {
    message: 'Username must be at least 3 characters.',
  }).max(50).optional().or(z.literal('')),
  full_name: z.string().optional().or(z.literal('')),
});

type ProfileFormValues = z.infer<typeof profileFormSchema>;

interface UserProfile {
  id: string;
  username?: string | null;
  full_name?: string | null;
  email: string;
  role: string;
}

export function ProfileForm({ user }: { user: UserProfile }) {
  const [isLoading, setIsLoading] = useState(false);

  const form = useForm<ProfileFormValues>({
    resolver: zodResolver(profileFormSchema),
    defaultValues: {
      username: user.username || '',
      full_name: user.full_name || '',
    },
  });

  async function onSubmit(data: ProfileFormValues) {
    setIsLoading(true);
    const formData = new FormData();
    formData.append('username', data.username || '');
    formData.append('full_name', data.full_name || '');

    const result = await updateProfile(user.id, formData);
    setIsLoading(false);

    if (result.error) {
      toast.error(result.error);
    } else {
      toast.success('Profile updated successfully.');
    }
  }

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
        <FormField
          control={form.control}
          name="username"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Username</FormLabel>
              <FormControl>
                <Input placeholder="johndoe" {...field} />
              </FormControl>
              <FormDescription>
                This is your public display name.
              </FormDescription>
              <FormMessage />
            </FormItem>
          )}
        />
        <FormField
          control={form.control}
          name="full_name"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Full Name</FormLabel>
              <FormControl>
                <Input placeholder="John Doe" {...field} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
        <div className="space-y-2">
          <FormLabel>Email</FormLabel>
          <Input value={user.email} disabled />
          <FormDescription>Your email address is managed by your authentication provider.</FormDescription>
        </div>
        <div className="space-y-2">
          <FormLabel>Role</FormLabel>
          <Input value={user.role} disabled className="capitalize" />
        </div>
        <Button type="submit" disabled={isLoading}>
          {isLoading ? 'Saving...' : 'Save changes'}
        </Button>
      </form>
    </Form>
  );
}
