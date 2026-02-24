export const dynamic = 'force-dynamic';
import { fetchServer } from '@/lib/api';
import { Card, CardContent } from '@/components/ui/card';
import Link from 'next/link';

export default async function MessagesPage() {
  const res = await fetchServer('/api/conversations');
  const conversations = res.ok ? await res.json() : [];

  return (
    <main className="container mx-auto py-10 px-4 max-w-4xl">
      <h1 className="text-3xl font-bold mb-6">Messages</h1>
      <div className="space-y-4">
        {conversations.length === 0 ? (
          <p className="text-muted-foreground">No conversations yet.</p>
        ) : (
          conversations.map((conv: any) => (
            <Link key={conv.id} href={`/messages/${conv.id}`} className="block">
              <Card className="hover:bg-muted/50 transition-colors">
                <CardContent className="p-4 flex items-center gap-4">
                  <div className="flex-1">
                    <div className="font-semibold">
                       {conv.participants.map((p: any) => p.username || 'Unknown').join(', ')}
                    </div>
                    <div className="text-sm text-muted-foreground line-clamp-1 mt-1">
                       {conv.last_message ? conv.last_message.content : 'No messages yet.'}
                    </div>
                  </div>
                  <div className="text-xs text-muted-foreground">
                     {conv.updated_at ? new Date(conv.updated_at).toLocaleDateString() : ''}
                  </div>
                </CardContent>
              </Card>
            </Link>
          ))
        )}
      </div>
    </main>
  );
}
