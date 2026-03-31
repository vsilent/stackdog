import '@testing-library/jest-dom';

// Mock WebSocket
class MockWebSocket {
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSING = 2;
  static CLOSED = 3;

  url: string;
  readyState = MockWebSocket.OPEN;
  send = jest.fn();
  close = jest.fn();
  addEventListener = jest.fn();
  removeEventListener = jest.fn();

  constructor(url: string) {
    this.url = url;
  }
}

global.WebSocket = MockWebSocket as unknown as typeof WebSocket;

// Mock fetch
global.fetch = jest.fn();
