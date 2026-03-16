import React from 'react';
import { Card } from 'react-bootstrap';
import './SecurityScore.css';

interface SecurityScoreProps {
  score: number;
}

const SecurityScore: React.FC<SecurityScoreProps> = ({ score }) => {
  const getScoreColor = (score: number): string => {
    if (score >= 80) return '#27ae60'; // Green
    if (score >= 60) return '#f39c12'; // Orange
    if (score >= 40) return '#e67e22'; // Dark Orange
    return '#e74c3c'; // Red
  };

  const getScoreLabel = (score: number): string => {
    if (score >= 80) return 'Secure';
    if (score >= 60) return 'Moderate';
    if (score >= 40) return 'At Risk';
    return 'Critical';
  };

  const rotation = (score / 100) * 180 - 90;

  return (
    <Card className="security-score-card">
      <Card.Body>
        <Card.Title>Security Score</Card.Title>
        <div className="gauge-container">
          <div className="gauge">
            <div className="gauge-background">
              <div className="gauge-fill" style={{ transform: `rotate(${rotation}deg)` }} />
            </div>
            <div className="gauge-cover">
              <span className="gauge-value">{score}</span>
            </div>
          </div>
        </div>
        <div className="score-label" style={{ color: getScoreColor(score) }}>
          {getScoreLabel(score)}
        </div>
      </Card.Body>
    </Card>
  );
};

export default SecurityScore;
