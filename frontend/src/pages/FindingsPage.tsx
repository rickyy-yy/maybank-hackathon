import React, { useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Filter, Download, RefreshCw } from 'lucide-react';
import { useFindings } from '../hooks/useFindings';
import FindingsTable from '../components/findings/FindingsTable';
import api from '../services/api';

const FindingsPage: React.FC = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const scanId = searchParams.get('scan_id') || undefined;
  
  const [filters, setFilters] = useState({
    severity: searchParams.get('severity') || '',
    status: searchParams.get('status') || '',
  });

  const { data, isLoading, refetch } = useFindings({
    scanId,
    severity: filters.severity || undefined,
    status: filters.status || undefined,
  });

  const handleFilterChange = (key: string, value: string) => {
    const newFilters = { ...filters, [key]: value };
    setFilters(newFilters);
    
    const newParams = new URLSearchParams(searchParams);
    if (value) {
      newParams.set(key, value);
    } else {
      newParams.delete(key);
    }
    setSearchParams(newParams);
  };

  const handleCreateTickets = async (findingIds: string[]) => {
    try {
      const response = await api.post('/api/v1/integrations/jira/create-tickets', {
        finding_ids: findingIds,
      });

      if (response.data.success) {
        alert(
          `Successfully created ${response.data.created} ticket(s).\n` +
          (response.data.failed > 0 ? `Failed: ${response.data.failed}` : '')
        );
        refetch();
      }
    } catch (error: any) {
      const message = error.response?.data?.detail || 'Failed to create Jira tickets';
      alert(`Error: ${message}`);
    }
  };

  const handleExportCSV = () => {
    if (!data?.findings) return;

    const headers = ['Severity', 'Title', 'Asset', 'CVSS', 'CVE', 'Status', 'Priority'];
    const rows = data.findings.map(f => [
      f.severity,
      f.title,
      f.affected_asset,
      f.cvss_score?.toString() || 'N/A',
      f.cve_id || 'N/A',
      f.status,
      f.priority_rank?.toString() || 'N/A'
    ]);

    const csv = [headers, ...rows].map(row => row.join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `findings-${new Date().toISOString()}.csv`;
    a.click();
  };

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
  const total = data?.total || 0;

  return (
    <div>
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 mb-2">Security Findings</h1>
          <p className="text-gray-600">
            {total} finding{total !== 1 ? 's' : ''} discovered
            {scanId && ' in selected scan'}
          </p>
        </div>
        <div className="flex gap-2">
          <button 
            onClick={() => refetch()}
            className="btn-secondary flex items-center gap-2"
          >
            <RefreshCw className="w-4 h-4" />
            Refresh
          </button>
          <button 
            onClick={handleExportCSV}
            disabled={findings.length === 0}
            className="btn-secondary flex items-center gap-2"
          >
            <Download className="w-4 h-4" />
            Export CSV
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="card mb-6">
        <div className="flex items-center gap-4">
          <Filter className="w-5 h-5 text-gray-400" />
          <div className="flex gap-4 flex-1">
            <select
              value={filters.severity}
              onChange={(e) => handleFilterChange('severity', e.target.value)}
              className="px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
            >
              <option value="">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
              <option value="INFO">Info</option>
            </select>

            <select
              value={filters.status}
              onChange={(e) => handleFilterChange('status', e.target.value)}
              className="px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
            >
              <option value="">All Statuses</option>
              <option value="open">Open</option>
              <option value="in_progress">In Progress</option>
              <option value="resolved">Resolved</option>
              <option value="false_positive">False Positive</option>
            </select>

            {(filters.severity || filters.status) && (
              <button
                onClick={() => {
                  setFilters({ severity: '', status: '' });
                  setSearchParams(scanId ? { scan_id: scanId } : {});
                }}
                className="text-sm text-blue-600 hover:text-blue-800"
              >
                Clear Filters
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Summary Stats */}
      {total > 0 && (
        <div className="grid grid-cols-5 gap-4 mb-6">
          {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map(severity => {
            const count = findings.filter(f => f.severity === severity).length;
            const colors = {
              CRITICAL: 'text-red-600 bg-red-50',
              HIGH: 'text-orange-600 bg-orange-50',
              MEDIUM: 'text-yellow-600 bg-yellow-50',
              LOW: 'text-green-600 bg-green-50',
              INFO: 'text-blue-600 bg-blue-50'
            };
            return (
              <div key={severity} className={`card ${colors[severity as keyof typeof colors]}`}>
                <div className="text-2xl font-bold">{count}</div>
                <div className="text-sm font-medium">{severity}</div>
              </div>
            );
          })}
        </div>
      )}

      {/* Findings Table */}
      {findings.length > 0 ? (
        <FindingsTable
          findings={findings}
          onSelectFinding={(finding) => console.log('Selected:', finding)}
          onCreateTicket={handleCreateTickets}
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