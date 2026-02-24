'use server';

import { fetchServer } from '@/lib/server';
import { revalidatePath } from 'next/cache';

export async function updateProfile(userId: string, formData: FormData) {
  const username = formData.get('username') as string;
  const full_name = formData.get('full_name') as string;

  const res = await fetchServer(`/api/users/${userId}`, {
    method: 'PUT',
    body: JSON.stringify({
      username: username || undefined,
      full_name: full_name || undefined,
    }),
  });

  if (!res.ok) {
    const errorText = await res.text();
    return { error: `Failed to update profile: ${res.statusText}. ${errorText}` };
  }

  revalidatePath('/profile');
  return { success: true };
}
