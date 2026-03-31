import React from 'react';
import './Sidebar.css';

const DASHBOARD_LOGO_URL = 'https://github.com/user-attachments/assets/0c8a9216-8315-4ef7-9b73-d96c40521ed1';

const Sidebar: React.FC = () => {
  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <img
          src={DASHBOARD_LOGO_URL}
          alt="Stackdog logo"
          className="sidebar-logo"
          width={39}
          height={39}
        />
        <span>Stackdog</span>
      </div>
      <nav className="sidebar-nav">
        <a href="#overview">Overview</a>
        <a href="#threats">Threat Map</a>
        <a href="#alerts">Alerts</a>
        <a href="#containers">Containers</a>
      </nav>
    </aside>
  );
};

export default Sidebar;
