import React, { useEffect, useState } from 'react';
import { Card, Button, Form, Badge, Modal, Spinner, Alert as BootstrapAlert } from 'react-bootstrap';
import apiService from '../services/api';
import { Container, ContainerStatus } from '../types/containers';
import './ContainerList.css';

const ContainerList: React.FC = () => {
  const [containers, setContainers] = useState<Container[]>([]);
  const [loading, setLoading] = useState(true);
  const [filterStatus, setFilterStatus] = useState<ContainerStatus | ''>('');
  const [showModal, setShowModal] = useState(false);
  const [selectedContainer, setSelectedContainer] = useState<Container | null>(null);
  const [showQuarantineModal, setShowQuarantineModal] = useState(false);
  const [quarantineReason, setQuarantineReason] = useState('');

  useEffect(() => {
    loadContainers();
  }, [filterStatus]);

  const loadContainers = async () => {
    try {
      setLoading(true);
      const data = await apiService.getContainers();
      setContainers(filterStatus ? data.filter((c: Container) => c.status === filterStatus) : data);
    } catch (err) {
      console.error('Error loading containers:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleQuarantine = async () => {
    if (!selectedContainer) return;
    try {
      await apiService.quarantineContainer({
        containerId: selectedContainer.id,
        reason: quarantineReason || 'Quarantined via dashboard',
      });
      setShowQuarantineModal(false);
      loadContainers();
    } catch (err) {
      console.error('Failed to quarantine container:', err);
    }
  };

  const handleRelease = async (containerId: string) => {
    try {
      await apiService.releaseContainer(containerId);
      loadContainers();
    } catch (err) {
      console.error('Failed to release container:', err);
    }
  };

  const getStatusBadge = (status: ContainerStatus) => {
    const variants: Record<ContainerStatus, string> = {
      Running: 'success',
      Stopped: 'secondary',
      Paused: 'warning',
      Quarantined: 'danger',
    };
    return variants[status];
  };

  const getSecurityBadge = (state: string) => {
    const variants: Record<string, string> = {
      Secure: 'success',
      AtRisk: 'warning',
      Compromised: 'danger',
      Quarantined: 'danger',
    };
    return variants[state] || 'secondary';
  };

  const getRiskColor = (score: number) => {
    if (score < 30) return '#27ae60';
    if (score < 60) return '#f39c12';
    return '#e74c3c';
  };

  return (
    <Card className="container-list">
      <Card.Header>
        <Card.Title>Containers</Card.Title>
      </Card.Header>
      <Card.Body>
        <Form.Group className="mb-3">
          <Form.Label>Filter by status</Form.Label>
          <Form.Select
            aria-label="Filter by status"
            value={filterStatus}
            onChange={(e) => setFilterStatus(e.target.value as ContainerStatus | '')}
          >
            <option value="">All Statuses</option>
            <option value="Running">Running</option>
            <option value="Stopped">Stopped</option>
            <option value="Paused">Paused</option>
            <option value="Quarantined">Quarantined</option>
          </Form.Select>
        </Form.Group>

        {loading ? (
          <div className="text-center">
            <Spinner animation="border" />
          </div>
        ) : (
          <div className="container-items">
            {containers.map((container) => (
              <div key={container.id} className="container-item">
                <div className="container-header">
                  <h5>{container.name}</h5>
                  <Badge bg={getStatusBadge(container.status)}>{container.status}</Badge>
                </div>
                <div className="container-details">
                  <p className="mb-1"><strong>Image:</strong> {container.image}</p>
                  <p className="mb-1">
                    <strong>Security:</strong>{' '}
                    <Badge bg={getSecurityBadge(container.securityStatus.state)}>
                      {container.securityStatus.state}
                    </Badge>
                  </p>
                  <p className="mb-1">
                    <strong>Risk Score:</strong>{' '}
                    <span style={{ color: getRiskColor(container.riskScore) }}>
                      {container.riskScore}
                    </span>
                  </p>
                  <div className="network-activity">
                    <small>
                      📥 {container.networkActivity.inboundConnections} | 
                      📤 {container.networkActivity.outboundConnections} | 
                      🚫 {container.networkActivity.blockedConnections}
                    </small>
                    {container.networkActivity.suspiciousActivity && (
                      <Badge bg="danger" className="ms-2">Suspicious</Badge>
                    )}
                  </div>
                </div>
                <div className="container-actions">
                  <Button
                    variant="outline-primary"
                    size="sm"
                    onClick={() => {
                      setSelectedContainer(container);
                      setShowModal(true);
                    }}
                  >
                    Details
                  </Button>
                  {container.status === 'Running' && (
                    <Button
                      variant="outline-danger"
                      size="sm"
                      onClick={() => {
                        setSelectedContainer(container);
                        setShowQuarantineModal(true);
                      }}
                    >
                      Quarantine
                    </Button>
                  )}
                  {container.status === 'Quarantined' && (
                    <Button
                      variant="outline-success"
                      size="sm"
                      onClick={() => handleRelease(container.id)}
                    >
                      Release
                    </Button>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </Card.Body>

      {/* Detail Modal */}
      <Modal show={showModal} onHide={() => setShowModal(false)}>
        <Modal.Header closeButton>
          <Modal.Title>Container Details</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          {selectedContainer && (
            <div>
              <p><strong>Name:</strong> {selectedContainer.name}</p>
              <p><strong>ID:</strong> {selectedContainer.id}</p>
              <p><strong>Image:</strong> {selectedContainer.image}</p>
              <p><strong>Status:</strong> {selectedContainer.status}</p>
              <p><strong>Security:</strong> {selectedContainer.securityStatus.state}</p>
              <p><strong>Risk Score:</strong> {selectedContainer.riskScore}</p>
              <p><strong>Threats:</strong> {selectedContainer.securityStatus.threats}</p>
              <p><strong>Vulnerabilities:</strong> {selectedContainer.securityStatus.vulnerabilities}</p>
              <p><strong>Last Scan:</strong> {new Date(selectedContainer.securityStatus.lastScan).toLocaleString()}</p>
            </div>
          )}
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={() => setShowModal(false)}>Close</Button>
        </Modal.Footer>
      </Modal>

      {/* Quarantine Modal */}
      <Modal show={showQuarantineModal} onHide={() => setShowQuarantineModal(false)}>
        <Modal.Header closeButton>
          <Modal.Title>Confirm Quarantine</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <p>Are you sure you want to quarantine this container?</p>
          <Form.Group>
            <Form.Label>Reason</Form.Label>
            <Form.Control
              as="textarea"
              rows={3}
              value={quarantineReason}
              onChange={(e) => setQuarantineReason(e.target.value)}
              placeholder="Enter reason for quarantine..."
            />
          </Form.Group>
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={() => setShowQuarantineModal(false)}>Cancel</Button>
          <Button variant="danger" onClick={handleQuarantine}>Confirm</Button>
        </Modal.Footer>
      </Modal>
    </Card>
  );
};

export default ContainerList;
