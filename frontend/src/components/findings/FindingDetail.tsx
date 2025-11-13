import React from 'react';
import { Finding } from '../../types/finding';

interface FindingDetailProps {
  finding: Finding;
}

const FindingDetail: React.FC<FindingDetailProps> = ({ finding }) => {
  return (
    <div className="card">
      <h2 className="text-2xl font-bold mb-4">{finding.title}</h2>
      <div className="space-y-4">
        <div>
          <span className="text-sm font-semibold text-gray-700">Severity: </span>
          <span className={`px-2 py-1 text-xs font-semibold rounded`}>
            {finding.severity}
          </span>
        </div>
        <div>
          <p className="text-sm text-gray-600">{finding.description}</p>
        </div>
      </div>
    </div>
  );
};

export default FindingDetail;