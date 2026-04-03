import axios, { AxiosInstance } from 'axios';
import { SecurityStatus, Threat, ThreatStatistics } from '../types/security';
import { Alert, AlertStats, AlertFilter } from '../types/alerts';
import { Container, QuarantineRequest } from '../types/containers';

type EnvLike = {
  REACT_APP_API_URL?: string;
  APP_PORT?: string;
  REACT_APP_API_PORT?: string;
};

const env = ((globalThis as unknown as { __STACKDOG_ENV__?: EnvLike }).__STACKDOG_ENV__ ??
  {}) as EnvLike;
const apiPort = env.REACT_APP_API_PORT || env.APP_PORT || '5555';
const API_BASE_URL = env.REACT_APP_API_URL || `http://localhost:${apiPort}/api`;

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

  private firstNumber(...values: unknown[]): number | null {
    return (values.find((value) => typeof value === 'number') as number | undefined) ?? null;
  }

  private firstString(...values: unknown[]): string | null {
    return (
      (values.find((value) => typeof value === 'string' && value.length > 0) as string | undefined) ??
      null
    );
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
    const response = await this.api.get('/threats/statistics');
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
    const raw = response.data as Array<Record<string, any>>;
    return raw.map((item) => {
      const securityStatus = item.securityStatus ?? item.security_status ?? {};
      const networkActivity = item.networkActivity ?? item.network_activity ?? {};

        return {
          id: item.id ?? '',
          name: item.name ?? item.id ?? 'unknown',
          image: item.image ?? 'unknown',
          status: item.status ?? 'Running',
          securityStatus: {
            state: securityStatus.state ?? 'Secure',
            threats: securityStatus.threats ?? 0,
            vulnerabilities: this.firstNumber(securityStatus.vulnerabilities),
            lastScan: this.firstString(securityStatus.lastScan, securityStatus.last_scan),
          },
          riskScore: item.riskScore ?? item.risk_score ?? 0,
          networkActivity: {
            inboundConnections: this.firstNumber(
              networkActivity.inboundConnections,
              networkActivity.inbound_connections,
            ),
            outboundConnections: this.firstNumber(
              networkActivity.outboundConnections,
              networkActivity.outbound_connections,
            ),
            blockedConnections: this.firstNumber(
              networkActivity.blockedConnections,
              networkActivity.blocked_connections,
            ),
            receivedBytes: this.firstNumber(
              networkActivity.receivedBytes,
              networkActivity.received_bytes,
            ),
            transmittedBytes: this.firstNumber(
              networkActivity.transmittedBytes,
              networkActivity.transmitted_bytes,
            ),
            receivedPackets: this.firstNumber(
              networkActivity.receivedPackets,
              networkActivity.received_packets,
            ),
            transmittedPackets: this.firstNumber(
              networkActivity.transmittedPackets,
              networkActivity.transmitted_packets,
            ),
            suspiciousActivity: networkActivity.suspiciousActivity ?? networkActivity.suspicious_activity ?? false,
          },
          createdAt: item.createdAt ?? item.created_at ?? new Date().toISOString(),
      } as Container;
    });
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
