import React, { useEffect, useState } from 'react';
import { Card, Form, Spinner } from 'react-bootstrap';
import { BarChart, Bar, PieChart, Pie, LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, Cell } from 'recharts';
import apiService from '../services/api';
import { Threat, ThreatStatistics } from '../types/security';
import './ThreatMap.css';

const COLORS = ['#e74c3c', '#e67e22', '#f39c12', '#3498db', '#27ae60'];

const ThreatMap: React.FC = () => {
  const [threats, setThreats] = useState<Threat[]>([]);
  const [statistics, setStatistics] = useState<ThreatStatistics | null>(null);
  const [loading, setLoading] = useState(true);
  const [dateFrom, setDateFrom] = useState('');
  const [dateTo, setDateTo] = useState('');

  useEffect(() => {
    loadData();
  }, [dateFrom, dateTo]);

  const loadData = async () => {
    try {
      setLoading(true);
      const [threatsData, statsData] = await Promise.all([
        apiService.getThreats(),
        apiService.getThreatStatistics(),
      ]);
      setThreats(threatsData);
      setStatistics(statsData);
    } catch (err) {
      console.error('Error loading threat data:', err);
    } finally {
      setLoading(false);
    }
  };

  const getTypeData = () => {
    if (!statistics) return [];
    const byType = statistics.byType || {};
    return Object.entries(byType).map(([name, value]) => ({
      name,
      value,
    }));
  };

  const getSeverityData = () => {
    if (!statistics) return [];
    const bySeverity = statistics.bySeverity || {};
    return Object.entries(bySeverity).map(([name, value]) => ({
      name,
      value,
    }));
  };

  const getTimelineData = () => {
    // Group threats by date
    const grouped: Record<string, number> = {};
    threats.forEach((threat) => {
      const date = new Date(threat.timestamp).toLocaleDateString();
      grouped[date] = (grouped[date] || 0) + 1;
    });
    return Object.entries(grouped)
      .slice(-7)
      .map(([date, count]) => ({ date, count }));
  };

  return (
    <Card className="threat-map">
      <Card.Header>
        <Card.Title>Threat Map</Card.Title>
      </Card.Header>
      <Card.Body>
        {/* Date Filter */}
        <div className="threat-filters mb-4">
          <Form.Group className="filter-group">
            <Form.Label>From</Form.Label>
            <Form.Control
              type="date"
              value={dateFrom}
              onChange={(e) => setDateFrom(e.target.value)}
              aria-label="From"
            />
          </Form.Group>
          <Form.Group className="filter-group">
            <Form.Label>To</Form.Label>
            <Form.Control
              type="date"
              value={dateTo}
              onChange={(e) => setDateTo(e.target.value)}
              aria-label="To"
            />
          </Form.Group>
        </div>

        {loading ? (
          <div className="text-center">
            <Spinner animation="border" />
          </div>
        ) : (
          <>
            {/* Statistics Summary */}
            {statistics && (
              <div className="threat-summary mb-4">
                <div className="summary-item">
                  <span className="summary-label">Total Threats</span>
                  <span className="summary-value">{statistics.totalThreats}</span>
                </div>
                <div className="summary-item">
                  <span className="summary-label">Trend</span>
                  <span className={`summary-value ${statistics.trend}`}>
                    {statistics.trend === 'increasing' ? '📈' : statistics.trend === 'decreasing' ? '📉' : '➡️'}
                  </span>
                </div>
              </div>
            )}

            {/* Charts Row 1 */}
            <div className="charts-row">
              <div className="chart-container">
                <h5>Threat Type Distribution</h5>
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart data={getTypeData()}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="name" />
                    <YAxis />
                    <Tooltip />
                    <Legend />
                    <Bar dataKey="value" fill="#667eea">
                      {getTypeData().map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>

              <div className="chart-container">
                <h5>Severity Breakdown</h5>
                <ResponsiveContainer width="100%" height={300}>
                  <PieChart>
                    <Pie
                      data={getSeverityData()}
                      cx="50%"
                      cy="50%"
                      labelLine={false}
                      label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                      outerRadius={100}
                      fill="#8884d8"
                      dataKey="value"
                    >
                      {getSeverityData().map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Charts Row 2 */}
            <div className="charts-row">
              <div className="chart-container full-width">
                <h5>Threat Timeline</h5>
                <ResponsiveContainer width="100%" height={300}>
                  <LineChart data={getTimelineData()}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="date" />
                    <YAxis />
                    <Tooltip />
                    <Legend />
                    <Line type="monotone" dataKey="count" stroke="#e74c3c" strokeWidth={2} name="Total Threats" />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Recent Threats List */}
            <div className="recent-threats">
              <h5>Recent Threats</h5>
              <div className="threat-list">
                {threats.slice(0, 5).map((threat) => (
                  <div key={threat.id} className="threat-item">
                    <div className="threat-info">
                      <span className="threat-type">{threat.type}</span>
                      <span className="threat-source">{threat.source}</span>
                    </div>
                    <div className="threat-meta">
                      <Badge severity={threat.severity}>{threat.severity}</Badge>
                      <span className="threat-score">Score: {threat.score}</span>
                      <span className="threat-time">{new Date(threat.timestamp).toLocaleString()}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </>
        )}
      </Card.Body>
    </Card>
  );
};

// Simple Badge component for threats
const Badge: React.FC<{ severity: string; children: React.ReactNode }> = ({ severity, children }) => {
  const colors: Record<string, string> = {
    Info: '#17a2b8',
    Low: '#28a745',
    Medium: '#ffc107',
    High: '#fd7e14',
    Critical: '#dc3545',
  };

  return (
    <span
      style={{
        backgroundColor: colors[severity] || '#6c757d',
        color: 'white',
        padding: '2px 8px',
        borderRadius: '12px',
        fontSize: '12px',
        fontWeight: 600,
      }}
    >
      {children}
    </span>
  );
};

export default ThreatMap;
