'use client';
import { useEffect, useRef, useState } from 'react';

interface Message {
  id: string;
  sender_id: string;
  content: string;
  created_at: string;
}

export function useChatWebSocket(conversationId: string) {
  const [messages, setMessages] = useState<Message[]>([]);
  const ws = useRef<WebSocket | null>(null);

  useEffect(() => {
    let active = true;
    let socket: WebSocket | null = null;

    async function connect() {
      try {
        const res = await fetch('/api/auth/token');
        if (!res.ok) {
          console.error('Failed to fetch auth token for websocket', res.status);
          return;
        }
        const { accessToken } = await res.json();

        const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8080';
        const wsUrl = apiUrl.replace(/^http/, 'ws');

        socket = new WebSocket(`${wsUrl}/api/ws`);

        socket.onopen = () => {
          if (!active || !socket || socket.readyState !== WebSocket.OPEN) {
            return;
          }
          socket.send(
            JSON.stringify({
              type: 'auth',
              payload: { token: accessToken, conversation_id: conversationId },
            }),
          );
        };

        socket.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            if (
              active &&
              ws.current === socket &&
              socket &&
              socket.readyState === WebSocket.OPEN &&
              data.type === 'message'
            ) {
              setMessages((prev) => [...prev, data.payload]);
            }
          } catch (e) {
            console.error('Failed to parse WS message', e);
          }
        };

        if (active) {
          ws.current = socket;
        } else if (socket) {
          socket.onmessage = null;
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
        socket.onmessage = null;
        socket.close();
      }
      ws.current = null;
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
