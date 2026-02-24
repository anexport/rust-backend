export const dynamic = 'force-dynamic';
import { fetchServer } from '@/lib/api';
import { Card, CardContent } from '@/components/ui/card';
import Link from 'next/link';

interface ConversationParticipant {
  username?: string | null;
}

interface ConversationPreview {
  id: string;
  participants?: ConversationParticipant[] | null;
  last_message?: { content?: string | null } | null;
  updated_at?: string | null;
}

export default async function MessagesPage() {
  let conversations: ConversationPreview[] = [];
  try {
    const res = await fetchServer('/api/conversations');
    if (!res.ok) {
      console.error('Failed to fetch conversations', res.status);
    } else {
      const payload: unknown = await res.json();
      if (Array.isArray(payload)) {
        conversations = payload as ConversationPreview[];
      } else if (
        payload &&
        typeof payload === 'object' &&
        Array.isArray((payload as { results?: unknown[] }).results)
      ) {
        conversations = (payload as { results: ConversationPreview[] }).results;
      } else {
        conversations = [];
        console.warn('Unexpected conversations payload shape');
      }
    }
  } catch (error) {
    console.error('Failed to fetch conversations', error);
  }

  return (
    <main className="container mx-auto py-10 px-4 max-w-4xl">
      <h1 className="text-3xl font-bold mb-6">Messages</h1>
      <div className="space-y-4">
        {conversations.length === 0 ? (
          <p className="text-muted-foreground">No conversations yet.</p>
        ) : (
          conversations.map((conv) => (
            <Link key={conv.id} href={`/messages/${conv.id}`} className="block">
              <Card className="hover:bg-muted/50 transition-colors">
                <CardContent className="p-4 flex items-center gap-4">
                  <div className="flex-1">
                    <div className="font-semibold">
                      {(conv.participants ?? []).map((p) => p.username || 'Unknown').join(', ')}
                    </div>
                    <div className="text-sm text-muted-foreground line-clamp-1 mt-1">
                      {conv.last_message?.content?.trim() ? conv.last_message.content : 'No messages yet.'}
                    </div>
                  </div>
                  <div className="text-xs text-muted-foreground">
                    {conv.updated_at ? new Date(conv.updated_at).toLocaleDateString('en-US') : ''}
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
