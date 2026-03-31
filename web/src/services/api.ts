import axios, { AxiosInstance } from 'axios';
import { SecurityStatus, Threat, ThreatStatistics } from '../types/security';
import { Alert, AlertStats, AlertFilter } from '../types/alerts';
import { Container, QuarantineRequest } from '../types/containers';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000/api';

class ApiService {
  public api: AxiosInstance;

  constructor() {
    this.api = axios.create({
      baseURL: API_BASE_URL,
      timeout: 10000,
      headers: {
        'Content-Type': 'application/json',
      },
    });
  }

  // Security Status
  async getSecurityStatus(): Promise<SecurityStatus> {
    const response = await this.api.get('/security/status');
    return response.data;
  }

  async getThreats(): Promise<Threat[]> {
    const response = await this.api.get('/threats');
    return response.data;
  }

  async getThreatStatistics(): Promise<ThreatStatistics> {
    const response = await this.api.get('/statistics');
    return response.data;
  }

  // Alerts
  async getAlerts(filter?: AlertFilter): Promise<Alert[]> {
    const params = new URLSearchParams();
    if (filter?.severity) {
      filter.severity.forEach(s => params.append('severity', s));
    }
    if (filter?.status) {
      filter.status.forEach(s => params.append('status', s));
    }
    const response = await this.api.get('/alerts', { params });
    return response.data;
  }

  async getAlertStats(): Promise<AlertStats> {
    const response = await this.api.get('/alerts/stats');
    return response.data;
  }

  async acknowledgeAlert(alertId: string): Promise<void> {
    await this.api.post(`/alerts/${alertId}/acknowledge`);
  }

  async resolveAlert(alertId: string, note?: string): Promise<void> {
    await this.api.post(`/alerts/${alertId}/resolve`, { note });
  }

  // Containers
  async getContainers(): Promise<Container[]> {
    const response = await this.api.get('/containers');
    return response.data;
  }

  async quarantineContainer(request: QuarantineRequest): Promise<void> {
    await this.api.post(`/containers/${request.containerId}/quarantine`, {
      reason: request.reason,
    });
  }

  async releaseContainer(containerId: string): Promise<void> {
    await this.api.post(`/containers/${containerId}/release`);
  }
}

export const apiService = new ApiService();
export default apiService;
