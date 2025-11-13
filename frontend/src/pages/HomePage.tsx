import React from 'react';

const HomePage: React.FC = () => {
  return (
    <div>
      <h1 className="text-3xl font-bold mb-6">Welcome to VulnForge</h1>
      <div className="card">
        <p className="text-gray-600">
          VulnForge Remediation Engine transforms vulnerability scan data into actionable
          remediation tasks.
        </p>
      </div>
    </div>
  );
};

export default HomePage;