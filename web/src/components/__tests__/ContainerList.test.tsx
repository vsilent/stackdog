import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import ContainerList from '../ContainerList';
import apiService from '../../services/api';

// Mock services
jest.mock('../../services/api');

const mockContainers = [
  {
    id: 'container-1',
    name: 'web-server',
    image: 'nginx:latest',
    status: 'Running' as const,
    securityStatus: {
      state: 'Secure' as const,
      threats: 0,
      vulnerabilities: 0,
      lastScan: new Date().toISOString(),
    },
    riskScore: 10,
    networkActivity: {
      inboundConnections: 5,
      outboundConnections: 3,
      blockedConnections: 0,
      suspiciousActivity: false,
    },
    createdAt: new Date().toISOString(),
  },
  {
    id: 'container-2',
    name: 'database',
    image: 'postgres:13',
    status: 'Running' as const,
    securityStatus: {
      state: 'AtRisk' as const,
      threats: 2,
      vulnerabilities: 1,
      lastScan: new Date().toISOString(),
    },
    riskScore: 65,
    networkActivity: {
      inboundConnections: 10,
      outboundConnections: 5,
      blockedConnections: 2,
      suspiciousActivity: true,
    },
    createdAt: new Date().toISOString(),
  },
];

describe('ContainerList Component', () => {
  beforeEach(() => {
    (apiService.getContainers as jest.Mock).mockResolvedValue(mockContainers);
  });

  test('displays container list', async () => {
    render(<ContainerList />);

    await waitFor(() => {
      expect(screen.getByText('web-server')).toBeInTheDocument();
    });

    expect(screen.getByText('database')).toBeInTheDocument();
  });

  test('shows security status per container', async () => {
    render(<ContainerList />);

    await waitFor(() => {
      expect(screen.getByText('web-server')).toBeInTheDocument();
    });

    expect(screen.getByText('Secure')).toBeInTheDocument();
    expect(screen.getByText('At Risk')).toBeInTheDocument();
  });

  test('displays risk scores', async () => {
    render(<ContainerList />);

    await waitFor(() => {
      expect(screen.getByText('web-server')).toBeInTheDocument();
    });

    expect(screen.getByText('10')).toBeInTheDocument(); // Risk score
    expect(screen.getByText('65')).toBeInTheDocument();
  });

  test('quarantine button works', async () => {
    (apiService.quarantineContainer as jest.Mock).mockResolvedValue({});

    render(<ContainerList />);

    await waitFor(() => {
      expect(screen.getByText('database')).toBeInTheDocument();
    });

    const quarantineButton = screen.getByText('Quarantine');
    fireEvent.click(quarantineButton);

    // Should show confirmation modal
    expect(screen.getByText('Confirm Quarantine')).toBeInTheDocument();

    const confirmButton = screen.getByText('Confirm');
    fireEvent.click(confirmButton);

    await waitFor(() => {
      expect(apiService.quarantineContainer).toHaveBeenCalledWith({
        containerId: 'container-2',
        reason: expect.any(String),
      });
    });
  });

  test('release button works', async () => {
    const quarantinedContainer = {
      ...mockContainers[0],
      status: 'Quarantined' as const,
    };

    (apiService.getContainers as jest.Mock).mockResolvedValue([quarantinedContainer]);
    (apiService.releaseContainer as jest.Mock).mockResolvedValue({});

    render(<ContainerList />);

    await waitFor(() => {
      expect(screen.getByText('web-server')).toBeInTheDocument();
    });

    const releaseButton = screen.getByText('Release');
    fireEvent.click(releaseButton);

    await waitFor(() => {
      expect(apiService.releaseContainer).toHaveBeenCalledWith('container-1');
    });
  });

  test('filters by status', async () => {
    render(<ContainerList />);

    await waitFor(() => {
      expect(screen.getByText('web-server')).toBeInTheDocument();
    });

    const statusFilter = screen.getByLabelText('Filter by status');
    fireEvent.change(statusFilter, { target: { value: 'Running' } });

    // Should only show Running containers
    expect(screen.getByText('web-server')).toBeInTheDocument();
    expect(screen.getByText('database')).toBeInTheDocument();
  });

  test('shows network activity', async () => {
    render(<ContainerList />);

    await waitFor(() => {
      expect(screen.getByText('database')).toBeInTheDocument();
    });

    // Should show network activity details
    expect(screen.getByText('10')).toBeInTheDocument(); // Inbound
    expect(screen.getByText('5')).toBeInTheDocument(); // Outbound
    expect(screen.getByText('2')).toBeInTheDocument(); // Blocked
  });
});
