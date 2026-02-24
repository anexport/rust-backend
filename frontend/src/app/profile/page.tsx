export const dynamic = 'force-dynamic';
import { fetchServer } from '@/lib/api';
import { ProfileForm } from './ProfileForm';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { redirect } from 'next/navigation';

export default async function ProfilePage() {
  const res = await fetchServer('/api/auth/me');
  
  if (!res.ok) {
    if (res.status === 401) {
      redirect('/auth/login');
    }
    return <div className="p-8 text-center text-red-500">Failed to load profile.</div>;
  }

  const user = await res.json();

  return (
    <div className="container mx-auto py-10 px-4 max-w-2xl">
      <Card>
        <CardHeader>
          <CardTitle>Your Profile</CardTitle>
          <CardDescription>Update your personal information.</CardDescription>
        </CardHeader>
        <CardContent>
          <ProfileForm user={user} />
        </CardContent>
      </Card>
    </div>
  );
}
