export const dynamic = 'force-dynamic';
import { fetchServer } from '@/lib/api';
import { redirect } from 'next/navigation';
import ChatClient from './ChatClient';

interface Message {
  id: string;
  sender_id: string;
  content: string;
  created_at: string;
}

function isMessage(value: unknown): value is Message {
  if (!value || typeof value !== 'object') {
    return false;
  }
  const maybeMessage = value as Record<string, unknown>;
  return (
    typeof maybeMessage.id === 'string' &&
    typeof maybeMessage.sender_id === 'string' &&
    typeof maybeMessage.content === 'string' &&
    typeof maybeMessage.created_at === 'string'
  );
}

export default async function ConversationPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;

  let convRes: Response;
  let msgsRes: Response;
  let meRes: Response;
  try {
    [convRes, msgsRes, meRes] = await Promise.all([
      fetchServer(`/api/conversations/${id}`),
      fetchServer(`/api/conversations/${id}/messages`),
      fetchServer('/api/auth/me'),
    ]);
  } catch (error) {
    console.error('Failed to load conversation page data', error);
    return <div className="p-8 text-center text-red-500">Failed to load conversation.</div>;
  }

  if (!meRes.ok) {
    redirect('/auth/login');
  }

  let currentUser: { id: string } | null = null;
  try {
    currentUser = await meRes.json();
  } catch (error) {
    console.error('Failed to parse current user payload', error);
    redirect('/auth/login');
  }

  if (!currentUser?.id) {
    redirect('/auth/login');
  }

  if (!convRes.ok) {
    if (convRes.status === 403) {
      return <div className="p-8 text-center text-red-500">You do not have access to this conversation.</div>;
    }
    if (convRes.status === 404) {
      return <div className="p-8 text-center text-red-500">Conversation not found.</div>;
    }
    return <div className="p-8 text-center text-red-500">Failed to load conversation.</div>;
  }

  let initialMessages: unknown = [];
  if (msgsRes.ok) {
    try {
      initialMessages = await msgsRes.json();
    } catch (error) {
      console.error('Failed to parse conversation messages payload', error);
    }
  }

  const messageItems = Array.isArray((initialMessages as { items?: unknown[] }).items)
    ? (initialMessages as { items: unknown[] }).items
    : Array.isArray(initialMessages)
      ? initialMessages
      : [];
  const normalizedMessages = messageItems.filter(isMessage);

  return (
    <main className="container mx-auto py-10 px-4 max-w-4xl h-[calc(100vh-64px)] flex flex-col">
      <h1 className="text-2xl font-bold mb-4">Chat</h1>
      <ChatClient
        conversationId={id}
        initialMessages={normalizedMessages}
        currentUserId={currentUser.id}
      />
    </main>
  );
}
