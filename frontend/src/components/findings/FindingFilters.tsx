import React from 'react';

interface FindingFiltersProps {
  severity: string;
  status: string;
  onSeverityChange: (severity: string) => void;
  onStatusChange: (status: string) => void;
}

const FindingFilters: React.FC<FindingFiltersProps> = ({
  severity,
  status,
  onSeverityChange,
  onStatusChange,
}) => {
  return (
    <div className="flex gap-4">
      <select
        value={severity}
        onChange={(e) => onSeverityChange(e.target.value)}
        className="px-3 py-2 border border-gray-300 rounded-md"
      >
        <option value="">All Severities</option>
        <option value="CRITICAL">Critical</option>
        <option value="HIGH">High</option>
        <option value="MEDIUM">Medium</option>
        <option value="LOW">Low</option>
      </select>

      <select
        value={status}
        onChange={(e) => onStatusChange(e.target.value)}
        className="px-3 py-2 border border-gray-300 rounded-md"
      >
        <option value="">All Statuses</option>
        <option value="open">Open</option>
        <option value="in_progress">In Progress</option>
        <option value="resolved">Resolved</option>
        <option value="false_positive">False Positive</option>
      </select>
    </div>
  );
};

export default FindingFilters;