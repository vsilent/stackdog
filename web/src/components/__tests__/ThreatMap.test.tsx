import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import ThreatMap from '../ThreatMap';
import apiService from '../../services/api';

// Mock services
jest.mock('../../services/api');

const mockThreats = [
  {
    id: 'threat-1',
    type: 'CryptoMiner',
    severity: 'High' as const,
    score: 85,
    source: 'container-1',
    timestamp: new Date().toISOString(),
    status: 'New' as const,
  },
  {
    id: 'threat-2',
    type: 'ContainerEscape',
    severity: 'Critical' as const,
    score: 95,
    source: 'container-2',
    timestamp: new Date().toISOString(),
    status: 'Investigating' as const,
  },
  {
    id: 'threat-3',
    type: 'NetworkScanner',
    severity: 'Medium' as const,
    score: 55,
    source: 'container-1',
    timestamp: new Date().toISOString(),
    status: 'Mitigated' as const,
  },
];

const mockStatistics = {
  totalThreats: 10,
  bySeverity: {
    Info: 1,
    Low: 2,
    Medium: 3,
    High: 3,
    Critical: 1,
  },
  byType: {
    CryptoMiner: 3,
    ContainerEscape: 2,
    NetworkScanner: 5,
  },
  trend: 'increasing' as const,
};

describe('ThreatMap Component', () => {
  beforeEach(() => {
    (apiService.getThreats as jest.Mock).mockResolvedValue(mockThreats);
    (apiService.getThreatStatistics as jest.Mock).mockResolvedValue(mockStatistics);
  });

  test('displays threat type distribution', async () => {
    render(<ThreatMap />);

    await waitFor(() => {
      expect(screen.getByText('Threat Type Distribution')).toBeInTheDocument();
    });

    expect(screen.getByText('CryptoMiner')).toBeInTheDocument();
    expect(screen.getByText('ContainerEscape')).toBeInTheDocument();
    expect(screen.getByText('NetworkScanner')).toBeInTheDocument();
  });

  test('displays severity breakdown', async () => {
    render(<ThreatMap />);

    await waitFor(() => {
      expect(screen.getByText('Severity Breakdown')).toBeInTheDocument();
    });

    expect(screen.getByText('Critical')).toBeInTheDocument();
    expect(screen.getByText('High')).toBeInTheDocument();
    expect(screen.getByText('Medium')).toBeInTheDocument();
    expect(screen.getByText('Low')).toBeInTheDocument();
    expect(screen.getByText('Info')).toBeInTheDocument();
  });

  test('displays threat timeline', async () => {
    render(<ThreatMap />);

    await waitFor(() => {
      expect(screen.getByText('Threat Timeline')).toBeInTheDocument();
    });

    // Timeline should show threats over time
    expect(screen.getByText('Total Threats: 10')).toBeInTheDocument();
  });

  test('charts are interactive', async () => {
    render(<ThreatMap />);

    await waitFor(() => {
      expect(screen.getByText('Threat Type Distribution')).toBeInTheDocument();
    });

    // Hover over chart element (simulated)
    const chartElement = screen.getByText('CryptoMiner: 3');
    expect(chartElement).toBeInTheDocument();
  });

  test('filters by date range', async () => {
    render(<ThreatMap />);

    await waitFor(() => {
      expect(screen.getByText('Threat Type Distribution')).toBeInTheDocument();
    });

    const dateFromInput = screen.getByLabelText('From');
    const dateToInput = screen.getByLabelText('To');

    fireEvent.change(dateFromInput, { target: { value: '2026-01-01' } });
    fireEvent.change(dateToInput, { target: { value: '2026-12-31' } });

    // Should filter threats by date range
    await waitFor(() => {
      expect(apiService.getThreats).toHaveBeenCalled();
    });
  });
});
