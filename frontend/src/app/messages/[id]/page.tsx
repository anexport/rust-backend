export const dynamic = 'force-dynamic';
import { fetchServer } from '@/lib/api';
import ChatClient from './ChatClient';

export default async function ConversationPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  
  const [convRes, msgsRes, meRes] = await Promise.all([
    fetchServer(`/api/conversations/${id}`),
    fetchServer(`/api/conversations/${id}/messages`),
    fetchServer('/api/auth/me')
  ]);

  if (!convRes.ok) {
    return <div className="p-8 text-center text-red-500">Conversation not found.</div>;
  }

  const conversation = await convRes.json();
  const initialMessages = msgsRes.ok ? await msgsRes.json() : [];
  const currentUser = meRes.ok ? await meRes.json() : null;

  return (
    <main className="container mx-auto py-10 px-4 max-w-4xl h-[calc(100vh-64px)] flex flex-col">
      <h1 className="text-2xl font-bold mb-4">Chat</h1>
      <ChatClient 
        conversationId={id} 
        initialMessages={initialMessages.items || initialMessages} 
        currentUserId={currentUser?.id} 
      />
    </main>
  );
}
