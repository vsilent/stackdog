import { WebSocketService, webSocketService } from '../websocket';

describe('WebSocket Service', () => {
  let ws: WebSocketService;

  beforeEach(() => {
    ws = new WebSocketService('ws://test-server');
    jest.clearAllMocks();
  });

  test('connects to WebSocket server', async () => {
    const mockWs = {
      onopen: null as (() => void) | null,
      onmessage: null as ((event: any) => void) | null,
      onclose: null as (() => void) | null,
      onerror: null as ((event: any) => void) | null,
      readyState: WebSocket.OPEN,
      send: jest.fn(),
      close: jest.fn(),
    };

    jest.spyOn(global, 'WebSocket').mockImplementation(() => mockWs as any);

    const connectPromise = ws.connect();

    // Simulate connection open
    mockWs.onopen!();

    await connectPromise;

    expect(global.WebSocket).toHaveBeenCalledWith('ws://test-server');
  });

  test('receives real-time updates', async () => {
    const mockWs = {
      onopen: null as (() => void) | null,
      onmessage: null as ((event: any) => void) | null,
      onclose: null as (() => void) | null,
      onerror: null as ((event: any) => void) | null,
      readyState: WebSocket.OPEN,
      send: jest.fn(),
      close: jest.fn(),
    };

    jest.spyOn(global, 'WebSocket').mockImplementation(() => mockWs as any);

    const handler = jest.fn();
    ws.subscribe('alert:created', handler);

    await ws.connect();

    // Simulate message received
    mockWs.onmessage!({
      data: JSON.stringify({
        type: 'alert:created',
        payload: { id: 'alert-1', message: 'Test' },
      }),
    });

    expect(handler).toHaveBeenCalledWith({ id: 'alert-1', message: 'Test' });
  });

  test('handles connection errors', async () => {
    const mockWs = {
      onopen: null as (() => void) | null,
      onmessage: null as ((event: any) => void) | null,
      onclose: null as (() => void) | null,
      onerror: null as ((event: any) => void) | null,
      readyState: WebSocket.CLOSED,
      send: jest.fn(),
      close: jest.fn(),
    };

    jest.spyOn(global, 'WebSocket').mockImplementation(() => mockWs as any);

    const errorHandler = jest.fn();

    try {
      await ws.connect();
    } catch (error) {
      errorHandler(error);
    }

    // Simulate error
    mockWs.onerror!({ message: 'Connection failed' });

    expect(errorHandler).toHaveBeenCalled();
  });

  test('reconnects on disconnect', async () => {
    jest.useFakeTimers();

    const mockWs = {
      onopen: null as (() => void) | null,
      onmessage: null as ((event: any) => void) | null,
      onclose: null as (() => void) | null,
      onerror: null as ((event: any) => void) | null,
      readyState: WebSocket.OPEN,
      send: jest.fn(),
      close: jest.fn(),
    };

    jest.spyOn(global, 'WebSocket').mockImplementation(() => mockWs as any);

    await ws.connect();

    // Simulate disconnect
    mockWs.onclose!();

    // Fast-forward time
    jest.advanceTimersByTime(2000);

    expect(global.WebSocket).toHaveBeenCalledTimes(2);

    jest.useRealTimers();
  });

  test('subscribes to events', () => {
    const handler = jest.fn();
    const unsubscribe = ws.subscribe('threat:detected', handler);

    expect(typeof unsubscribe).toBe('function');
  });

  test('unsubscribes from events', () => {
    const handler = jest.fn();
    const unsubscribe = ws.subscribe('threat:detected', handler);

    unsubscribe();

    // Handler should not be called after unsubscribe
    expect(ws['eventHandlers'].get('threat:detected')?.has(handler)).toBe(false);
  });

  test('sends messages', async () => {
    const mockWs = {
      onopen: null as (() => void) | null,
      onmessage: null as ((event: any) => void) | null,
      onclose: null as (() => void) | null,
      onerror: null as ((event: any) => void) | null,
      readyState: WebSocket.OPEN,
      send: jest.fn(),
      close: jest.fn(),
    };

    jest.spyOn(global, 'WebSocket').mockImplementation(() => mockWs as any);

    await ws.connect();

    ws.send('alert:created', { id: 'alert-1' });

    expect(mockWs.send).toHaveBeenCalledWith(
      JSON.stringify({ type: 'alert:created', payload: { id: 'alert-1' } })
    );
  });

  test('checks connection status', async () => {
    const mockWs = {
      onopen: null as (() => void) | null,
      onmessage: null as ((event: any) => void) | null,
      onclose: null as (() => void) | null,
      onerror: null as ((event: any) => void) | null,
      readyState: WebSocket.OPEN,
      send: jest.fn(),
      close: jest.fn(),
    };

    jest.spyOn(global, 'WebSocket').mockImplementation(() => mockWs as any);

    expect(ws.isConnected()).toBe(false);

    await ws.connect();

    expect(ws.isConnected()).toBe(true);
  });
});
