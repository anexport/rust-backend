'use client';
import { useState } from 'react';
import { useChatWebSocket } from '@/hooks/useChatWebSocket';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { fetchClient } from '@/lib/api';

export default function ChatClient({ 
  conversationId, 
  initialMessages, 
  currentUserId 
}: { 
  conversationId: string; 
  initialMessages: any[]; 
  currentUserId: string;
}) {
  const { messages: liveMessages } = useChatWebSocket(conversationId);
  const [content, setContent] = useState('');
  
  const allMessages = [...initialMessages, ...liveMessages].sort(
    (a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime()
  );

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
        {allMessages.map((msg, i) => {
          const isMe = msg.sender_id === currentUserId;
          return (
            <div key={msg.id || i} className={`flex ${isMe ? 'justify-end' : 'justify-start'}`}>
              <div className={`max-w-[70%] rounded-lg p-3 ${isMe ? 'bg-primary text-primary-foreground' : 'bg-muted'}`}>
                <p className="text-sm">{msg.content}</p>
                <span className="text-[10px] opacity-70 mt-1 block">
                  {new Date(msg.created_at).toLocaleTimeString()}
                </span>
              </div>
            </div>
          );
        })}
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
