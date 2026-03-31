import React from 'react';
import './Sidebar.css';

const Sidebar: React.FC = () => {
  return (
    <aside className="sidebar">
      <div className="sidebar-brand">Stackdog</div>
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
