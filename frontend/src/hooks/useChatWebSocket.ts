'use client';
import { useEffect, useRef, useState } from 'react';

export function useChatWebSocket(conversationId: string) {
  const [messages, setMessages] = useState<any[]>([]);
  const ws = useRef<WebSocket | null>(null);

  useEffect(() => {
    let active = true;
    let socket: WebSocket;

    async function connect() {
      try {
        const res = await fetch('/api/auth/token');
        if (!res.ok) return;
        const { accessToken } = await res.json();
        
        const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8080';
        const wsUrl = apiUrl.replace(/^http/, 'ws');
        
        socket = new WebSocket(`${wsUrl}/api/ws`, ['bearer', accessToken]);

        socket.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            if (data.type === 'message') {
               setMessages(prev => [...prev, data.payload]);
            }
          } catch (e) {
            console.error('Failed to parse WS message', e);
          }
        };

        if (active) {
          ws.current = socket;
        } else {
          socket.close();
        }
      } catch (e) {
        console.error('WebSocket connection failed', e);
      }
    }

    connect();

    return () => {
      active = false;
      if (socket) {
        socket.close();
      }
    };
  }, [conversationId]);

  const sendMessage = (content: string) => {
    if (ws.current && ws.current.readyState === WebSocket.OPEN) {
      ws.current.send(JSON.stringify({
        type: 'sendMessage',
        payload: {
          conversation_id: conversationId,
          content,
        }
      }));
    }
  };

  return { messages, sendMessage };
}
