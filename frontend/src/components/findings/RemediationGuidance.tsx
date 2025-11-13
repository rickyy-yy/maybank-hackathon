import React from 'react';

interface RemediationGuidanceProps {
  guidance: string;
  effortHours?: number;
}

const RemediationGuidance: React.FC<RemediationGuidanceProps> = ({
  guidance,
  effortHours,
}) => {
  return (
    <div className="bg-blue-50 p-4 rounded border border-blue-200">
      <h3 className="font-semibold text-blue-900 mb-2">Remediation Guidance</h3>
      <p className="text-sm text-blue-800">{guidance}</p>
      {effortHours && (
        <p className="text-xs text-blue-600 mt-2">Estimated effort: {effortHours} hours</p>
      )}
    </div>
  );
};

export default RemediationGuidance;