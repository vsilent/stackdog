import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import AlertPanel from '../AlertPanel';
import apiService from '../../services/api';
import webSocketService from '../../services/websocket';

// Mock services
jest.mock('../../services/api');
jest.mock('../../services/websocket');

const mockAlerts = [
  {
    id: 'alert-1',
    alertType: 'ThreatDetected' as const,
    severity: 'High' as const,
    message: 'Suspicious activity detected',
    status: 'New' as const,
    timestamp: new Date().toISOString(),
  },
  {
    id: 'alert-2',
    alertType: 'RuleViolation' as const,
    severity: 'Medium' as const,
    message: 'Rule violation detected',
    status: 'Acknowledged' as const,
    timestamp: new Date().toISOString(),
  },
];

describe('AlertPanel Component', () => {
  beforeEach(() => {
    (apiService.getAlerts as jest.Mock).mockResolvedValue(mockAlerts);
    (apiService.getAlertStats as jest.Mock).mockResolvedValue({
      totalCount: 10,
      newCount: 5,
      acknowledgedCount: 3,
      resolvedCount: 2,
    });
  });

  test('lists alerts correctly', async () => {
    render(<AlertPanel />);

    await waitFor(() => {
      expect(screen.getByText('Suspicious activity detected')).toBeInTheDocument();
    });

    expect(screen.getByText('Rule violation detected')).toBeInTheDocument();
  });

  test('filters alerts by severity', async () => {
    render(<AlertPanel />);

    await waitFor(() => {
      expect(screen.getByText('Suspicious activity detected')).toBeInTheDocument();
    });

    const severityFilter = screen.getByLabelText('Filter by severity');
    fireEvent.change(severityFilter, { target: { value: 'High' } });

    // Should only show High severity alerts
    expect(screen.getByText('Suspicious activity detected')).toBeInTheDocument();
  });

  test('filters alerts by status', async () => {
    render(<AlertPanel />);

    await waitFor(() => {
      expect(screen.getByText('Suspicious activity detected')).toBeInTheDocument();
    });

    const statusFilter = screen.getByLabelText('Filter by status');
    fireEvent.change(statusFilter, { target: { value: 'New' } });

    // Should only show New alerts
    expect(screen.getByText('Suspicious activity detected')).toBeInTheDocument();
  });

  test('acknowledge alert works', async () => {
    (apiService.acknowledgeAlert as jest.Mock).mockResolvedValue({});

    render(<AlertPanel />);

    await waitFor(() => {
      expect(screen.getByText('Suspicious activity detected')).toBeInTheDocument();
    });

    const acknowledgeButton = screen.getByText('Acknowledge');
    fireEvent.click(acknowledgeButton);

    await waitFor(() => {
      expect(apiService.acknowledgeAlert).toHaveBeenCalledWith('alert-1');
    });
  });

  test('resolve alert works', async () => {
    (apiService.resolveAlert as jest.Mock).mockResolvedValue({});

    render(<AlertPanel />);

    await waitFor(() => {
      expect(screen.getByText('Suspicious activity detected')).toBeInTheDocument();
    });

    const resolveButton = screen.getByText('Resolve');
    fireEvent.click(resolveButton);

    await waitFor(() => {
      expect(apiService.resolveAlert).toHaveBeenCalledWith('alert-1', expect.any(String));
    });
  });

  test('displays alert statistics', async () => {
    render(<AlertPanel />);

    await waitFor(() => {
      expect(screen.getByText('10')).toBeInTheDocument();
    });

    expect(screen.getByText('5')).toBeInTheDocument(); // New
    expect(screen.getByText('3')).toBeInTheDocument(); // Acknowledged
    expect(screen.getByText('2')).toBeInTheDocument(); // Resolved
  });

  test('pagination works', async () => {
    const manyAlerts = Array.from({ length: 25 }, (_, i) => ({
      id: `alert-${i}`,
      alertType: 'ThreatDetected' as const,
      severity: 'High' as const,
      message: `Alert ${i}`,
      status: 'New' as const,
      timestamp: new Date().toISOString(),
    }));

    (apiService.getAlerts as jest.Mock).mockResolvedValue(manyAlerts);

    render(<AlertPanel />);

    await waitFor(() => {
      expect(screen.getByText('Alert 0')).toBeInTheDocument();
    });

    // Should show first 10 alerts
    expect(screen.getByText('Alert 0')).toBeInTheDocument();
    expect(screen.queryByText('Alert 15')).not.toBeInTheDocument();

    // Click next page
    const nextPageButton = screen.getByText('Next');
    fireEvent.click(nextPageButton);

    // Should show next 10 alerts
    await waitFor(() => {
      expect(screen.getByText('Alert 10')).toBeInTheDocument();
    });
  });

  test('bulk actions work', async () => {
    (apiService.acknowledgeAlert as jest.Mock).mockResolvedValue({});

    render(<AlertPanel />);

    await waitFor(() => {
      expect(screen.getByText('Suspicious activity detected')).toBeInTheDocument();
    });

    const selectAllCheckbox = screen.getByLabelText('Select all alerts');
    fireEvent.click(selectAllCheckbox);

    const bulkAcknowledgeButton = screen.getByText('Acknowledge Selected');
    fireEvent.click(bulkAcknowledgeButton);

    await waitFor(() => {
      expect(apiService.acknowledgeAlert).toHaveBeenCalled();
    });
  });
});
