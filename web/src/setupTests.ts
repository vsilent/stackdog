import '@testing-library/jest-dom';

// Mock WebSocket
global.WebSocket = class MockWebSocket {
  constructor(url: string) {
    this.url = url;
  }
  send = jest.fn();
  close = jest.fn();
  addEventListener = jest.fn();
  removeEventListener = jest.fn();
};

// Mock fetch
global.fetch = jest.fn();
