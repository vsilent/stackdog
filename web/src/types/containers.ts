// Container types

export interface Container {
  id: string;
  name: string;
  image: string;
  status: ContainerStatus;
  securityStatus: SecurityStatus;
  riskScore: number;
  networkActivity: NetworkActivity;
  createdAt: string;
}

export type ContainerStatus = 'Running' | 'Stopped' | 'Paused' | 'Quarantined';

export interface SecurityStatus {
  state: 'Secure' | 'AtRisk' | 'Compromised' | 'Quarantined';
  threats: number;
  vulnerabilities: number;
  lastScan: string;
}

export interface NetworkActivity {
  inboundConnections: number;
  outboundConnections: number;
  blockedConnections: number;
  suspiciousActivity: boolean;
}

export interface QuarantineRequest {
  containerId: string;
  reason: string;
}
