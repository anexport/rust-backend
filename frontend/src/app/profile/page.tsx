export const dynamic = 'force-dynamic';
import { fetchServer } from '@/lib/server';
import { ProfileForm } from './ProfileForm';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';

export default async function ProfilePage() {
  const res = await fetchServer('/api/auth/me');
  
  if (!res.ok) {
    if (res.status === 401) {
      return (
        <div className="p-8 text-center">
          <p className="mb-3">You need to log in to view your profile.</p>
          <a href="/auth/login" className="underline">
            Log in
          </a>
        </div>
      );
    }
    return <div className="p-8 text-center text-red-500">Failed to load profile.</div>;
  }

  const user = await res.json();

  return (
    <main className="container mx-auto py-10 px-4 md:px-6 max-w-7xl">
      <div className="max-w-2xl mx-auto">
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
    </main>
  );
}
