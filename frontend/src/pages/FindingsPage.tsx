import React, { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Filter, Download } from 'lucide-react';
import { useFindings } from '../hooks/useFindings';
import FindingsTable from '../components/findings/FindingsTable';

const FindingsPage: React.FC = () => {
  const [searchParams] = useSearchParams();
  const scanId = searchParams.get('scan_id') || undefined;
  
  const [filters, setFilters] = useState({
    severity: '',
    status: '',
  });

  const { data, isLoading } = useFindings({
    scanId,
    severity: filters.severity || undefined,
    status: filters.status || undefined,
  });

  if (isLoading) {
    return (
      <div className="card">
        <div className="text-center py-12">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
          <p className="text-gray-600">Loading findings...</p>
        </div>
      </div>
    );
  }

  const findings = data?.findings || [];

  return (
    <div>
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 mb-2">Security Findings</h1>
          <p className="text-gray-600">
            {data?.total || 0} findings discovered
            {scanId && ' in selected scan'}
          </p>
        </div>
        <button className="btn-secondary flex items-center gap-2">
          <Download className="w-4 h-4" />
          Export CSV
        </button>
      </div>

      {/* Filters */}
      <div className="card mb-6">
        <div className="flex items-center gap-4">
          <Filter className="w-5 h-5 text-gray-400" />
          <div className="flex gap-4 flex-1">
            <select
              value={filters.severity}
              onChange={(e) => setFilters({ ...filters, severity: e.target.value })}
              className="px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
            >
              <option value="">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>

            <select
              value={filters.status}
              onChange={(e) => setFilters({ ...filters, status: e.target.value })}
              className="px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
            >
              <option value="">All Statuses</option>
              <option value="open">Open</option>
              <option value="in_progress">In Progress</option>
              <option value="resolved">Resolved</option>
              <option value="false_positive">False Positive</option>
            </select>
          </div>
        </div>
      </div>

      {/* Findings Table */}
      {findings.length > 0 ? (
        <FindingsTable
          findings={findings}
          onSelectFinding={(finding) => console.log('Selected:', finding)}
          onCreateTicket={(ids) => console.log('Create tickets for:', ids)}
        />
      ) : (
        <div className="card text-center py-12">
          <p className="text-gray-500">No findings match the current filters</p>
        </div>
      )}
    </div>
  );
};

export default FindingsPage;