type WebSocketEvent = 
  | 'threat:detected'
  | 'alert:created'
  | 'alert:updated'
  | 'container:quarantined'
  | 'stats:updated';

type EventHandler = (data: any) => void;
type EnvLike = {
  REACT_APP_WS_URL?: string;
  APP_PORT?: string;
  REACT_APP_API_PORT?: string;
};

declare global {
  interface Window {
    __STACKDOG_ENV__?: EnvLike;
  }
}

export class WebSocketService {
  private ws: WebSocket | null = null;
  private url: string;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private reconnectDelay = 1000;
  private eventHandlers: Map<WebSocketEvent, Set<EventHandler>> = new Map();
  private shouldReconnect = true;

  constructor(url?: string) {
    const env = ((globalThis as { __STACKDOG_ENV__?: EnvLike }).__STACKDOG_ENV__ ??
      {}) as EnvLike;
    const apiPort = env.REACT_APP_API_PORT || env.APP_PORT || '5555';
    this.url = url || env.REACT_APP_WS_URL || `ws://localhost:${apiPort}/ws`;
  }

  connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      try {
        this.ws = new WebSocket(this.url);

        this.ws.onopen = () => {
          console.log('WebSocket connected');
          this.reconnectAttempts = 0;
          resolve();
        };

        this.ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            this.handleEvent(data.type, data.payload);
          } catch (error) {
            console.error('Failed to parse WebSocket message:', error);
          }
        };

        this.ws.onclose = () => {
          console.log('WebSocket disconnected');
          if (this.shouldReconnect && this.reconnectAttempts < this.maxReconnectAttempts) {
            this.scheduleReconnect();
          }
        };

        this.ws.onerror = (error) => {
          console.error('WebSocket error:', error);
          reject(error);
        };
      } catch (error) {
        reject(error);
      }
    });
  }

  private scheduleReconnect() {
    this.reconnectAttempts++;
    const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1);
    console.log(`Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts})`);
    
    setTimeout(() => {
      this.connect().catch(console.error);
    }, delay);
  }

  private handleEvent(type: string, payload: any) {
    const handlers = this.eventHandlers.get(type as WebSocketEvent);
    if (handlers) {
      handlers.forEach(handler => handler(payload));
    }
  }

  subscribe(event: WebSocketEvent, handler: EventHandler): () => void {
    if (!this.eventHandlers.has(event)) {
      this.eventHandlers.set(event, new Set());
    }
    this.eventHandlers.get(event)!.add(handler);

    // Return unsubscribe function
    return () => {
      this.eventHandlers.get(event)?.delete(handler);
    };
  }

  send(type: WebSocketEvent, payload: any): void {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify({ type, payload }));
    } else {
      console.warn('WebSocket not connected, message not sent');
    }
  }

  disconnect(): void {
    this.shouldReconnect = false;
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
    this.eventHandlers.clear();
  }

  isConnected(): boolean {
    return this.ws !== null && this.ws.readyState === WebSocket.OPEN;
  }
}

export const webSocketService = new WebSocketService();
export default webSocketService;
