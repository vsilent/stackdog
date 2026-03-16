import apiService from '../api';
import { AlertSeverity, AlertStatus } from '../../types/alerts';

// Mock axios
jest.mock('axios', () => ({
  create: () => ({
    get: jest.fn(),
    post: jest.fn(),
  }),
}));

describe('API Service', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('fetches security status from API', async () => {
    const mockStatus = {
      overallScore: 85,
      activeThreats: 3,
      quarantinedContainers: 1,
      alertsNew: 5,
      alertsAcknowledged: 2,
      lastUpdated: new Date().toISOString(),
    };

    (apiService.api.get as jest.Mock).mockResolvedValue({ data: mockStatus });

    const status = await apiService.getSecurityStatus();

    expect(apiService.api.get).toHaveBeenCalledWith('/security/status');
    expect(status).toEqual(mockStatus);
  });

  test('fetches alerts from API', async () => {
    const mockAlerts = [
      {
        id: 'alert-1',
        alertType: 'ThreatDetected',
        severity: 'High',
        message: 'Test alert',
        status: 'New',
        timestamp: new Date().toISOString(),
      },
    ];

    (apiService.api.get as jest.Mock).mockResolvedValue({ data: mockAlerts });

    const alerts = await apiService.getAlerts();

    expect(apiService.api.get).toHaveBeenCalledWith('/alerts', expect.anything());
    expect(alerts).toEqual(mockAlerts);
  });

  test('acknowledges alert via API', async () => {
    (apiService.api.post as jest.Mock).mockResolvedValue({});

    await apiService.acknowledgeAlert('alert-123');

    expect(apiService.api.post).toHaveBeenCalledWith('/alerts/alert-123/acknowledge');
  });

  test('resolves alert via API', async () => {
    (apiService.api.post as jest.Mock).mockResolvedValue({});

    await apiService.resolveAlert('alert-123', 'Issue resolved');

    expect(apiService.api.post).toHaveBeenCalledWith('/alerts/alert-123/resolve', {
      note: 'Issue resolved',
    });
  });

  test('fetches containers from API', async () => {
    const mockContainers = [
      {
        id: 'container-1',
        name: 'test-container',
        status: 'Running',
        securityStatus: { state: 'Secure' as const },
        riskScore: 10,
      },
    ];

    (apiService.api.get as jest.Mock).mockResolvedValue({ data: mockContainers });

    const containers = await apiService.getContainers();

    expect(apiService.api.get).toHaveBeenCalledWith('/containers');
    expect(containers).toEqual(mockContainers);
  });

  test('quarantines container via API', async () => {
    (apiService.api.post as jest.Mock).mockResolvedValue({});

    await apiService.quarantineContainer({
      containerId: 'container-123',
      reason: 'Suspicious activity',
    });

    expect(apiService.api.post).toHaveBeenCalledWith(
      '/containers/container-123/quarantine',
      { reason: 'Suspicious activity' }
    );
  });
});
