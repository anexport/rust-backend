'use client';
import { useEffect, useMemo, useRef, useState } from 'react';
import { useChatWebSocket } from '@/hooks/useChatWebSocket';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { fetchClient } from '@/lib/api';

interface Message {
  id: string;
  sender_id: string;
  content: string;
  created_at: string;
}

function parseCreatedAt(value: string): number {
  const timestamp = Date.parse(value);
  return Number.isNaN(timestamp) ? 0 : timestamp;
}

function formatCreatedAtTime(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return '';
  }
  return date.toLocaleTimeString();
}

export default function ChatClient({
  conversationId,
  initialMessages,
  currentUserId,
}: {
  conversationId: string;
  initialMessages: Message[];
  currentUserId: string;
}) {
  const { messages: liveMessages } = useChatWebSocket(conversationId);
  const [content, setContent] = useState('');
  const messagesEndRef = useRef<HTMLDivElement | null>(null);

  const allMessages = useMemo(() => {
    const mergedById = new Map<string, Message>();
    [...initialMessages, ...liveMessages].forEach((message) => {
      if (message?.id) {
        mergedById.set(message.id, message);
      }
    });

    return Array.from(mergedById.values()).sort(
      (a, b) => parseCreatedAt(a.created_at) - parseCreatedAt(b.created_at),
    );
  }, [initialMessages, liveMessages]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth', block: 'end' });
  }, [allMessages]);

  const handleSend = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!content.trim()) return;

    try {
      await fetchClient(`/api/conversations/${conversationId}/messages`, {
        method: 'POST',
        body: JSON.stringify({ content })
      });
      setContent('');
    } catch (e) {
      console.error('Failed to send message', e);
    }
  };

  return (
    <div className="flex-1 flex flex-col bg-card rounded-lg border shadow-sm overflow-hidden">
      <div className="flex-1 p-4 overflow-y-auto space-y-4">
        {allMessages.map((msg) => {
          const isMe = msg.sender_id === currentUserId;
          return (
            <div key={msg.id} className={`flex ${isMe ? 'justify-end' : 'justify-start'}`}>
              <div className={`max-w-[70%] rounded-lg p-3 ${isMe ? 'bg-primary text-primary-foreground' : 'bg-muted'}`}>
                <p className="text-sm">{msg.content}</p>
                <span className="text-[10px] opacity-70 mt-1 block">
                  {formatCreatedAtTime(msg.created_at)}
                </span>
              </div>
            </div>
          );
        })}
        <div ref={messagesEndRef} />
      </div>
      <form onSubmit={handleSend} className="p-4 bg-background border-t flex gap-2">
        <Input 
          value={content}
          onChange={(e) => setContent(e.target.value)}
          placeholder="Type a message..."
          className="flex-1"
        />
        <Button type="submit">Send</Button>
      </form>
    </div>
  );
}
