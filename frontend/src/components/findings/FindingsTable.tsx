import React, { useState } from 'react';
import { ChevronDown, ChevronUp, ExternalLink, AlertCircle } from 'lucide-react';
import { Finding } from '../../types/finding';

interface FindingsTableProps {
  findings: Finding[];
  onSelectFinding: (finding: Finding) => void;
  onCreateTicket: (findingIds: string[]) => void;
}

const FindingsTable: React.FC<FindingsTableProps> = ({
  findings,
  onSelectFinding,
  onCreateTicket,
}) => {
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const getSeverityColor = (severity: string) => {
    const colors = {
      CRITICAL: 'bg-red-100 text-red-800 border-red-300',
      HIGH: 'bg-orange-100 text-orange-800 border-orange-300',
      MEDIUM: 'bg-yellow-100 text-yellow-800 border-yellow-300',
      LOW: 'bg-green-100 text-green-800 border-green-300',
      INFO: 'bg-blue-100 text-blue-800 border-blue-300',
    };
    return colors[severity as keyof typeof colors] || colors.INFO;
  };

  const toggleSelection = (id: string) => {
    const newSelected = new Set(selectedIds);
    if (newSelected.has(id)) {
      newSelected.delete(id);
    } else {
      newSelected.add(id);
    }
    setSelectedIds(newSelected);
  };

  const toggleExpand = (id: string) => {
    setExpandedId(expandedId === id ? null : id);
  };

  return (
    <div className="bg-white rounded-lg shadow">
      {/* Bulk Actions Bar */}
      {selectedIds.size > 0 && (
        <div className="bg-blue-50 px-4 py-3 border-b border-blue-200 flex items-center justify-between">
          <span className="text-sm text-blue-800">
            {selectedIds.size} finding{selectedIds.size > 1 ? 's' : ''} selected
          </span>
          <button
            onClick={() => onCreateTicket(Array.from(selectedIds))}
            className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 text-sm"
          >
            Create Jira Tickets
          </button>
        </div>
      )}

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-4 py-3 w-12">
                <input
                  type="checkbox"
                  checked={selectedIds.size === findings.length && findings.length > 0}
                  onChange={(e) => {
                    if (e.target.checked) {
                      setSelectedIds(new Set(findings.map((f) => f.id)));
                    } else {
                      setSelectedIds(new Set());
                    }
                  }}
                  className="rounded border-gray-300"
                />
              </th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                Severity
              </th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                Title
              </th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                Affected Asset
              </th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                CVSS
              </th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                Status
              </th>
              <th className="px-4 py-3 w-12"></th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {findings.map((finding) => (
              <React.Fragment key={finding.id}>
                <tr className="hover:bg-gray-50">
                  <td className="px-4 py-3" onClick={(e) => e.stopPropagation()}>
                    <input
                      type="checkbox"
                      checked={selectedIds.has(finding.id)}
                      onChange={() => toggleSelection(finding.id)}
                      className="rounded border-gray-300"
                    />
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap">
                    <span
                      className={`px-2 py-1 text-xs font-semibold rounded-full border ${getSeverityColor(
                        finding.severity
                      )}`}
                    >
                      {finding.severity}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-sm text-gray-900 max-w-md">
                    <div className="truncate">{finding.title}</div>
                    {finding.cve_id && (
                      <span className="text-xs text-gray-500">({finding.cve_id})</span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-sm text-gray-700">
                    <div className="flex flex-col">
                      <span className="font-mono text-xs">{finding.affected_asset}</span>
                      {finding.port && (
                        <span className="text-xs text-gray-500">
                          Port {finding.port}/{finding.protocol}
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap text-sm">
                    {finding.cvss_score ? (
                      <span className="font-semibold">{finding.cvss_score.toFixed(1)}</span>
                    ) : (
                      <span className="text-gray-400">N/A</span>
                    )}
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap text-sm">
                    <span
                      className={`px-2 py-1 text-xs rounded ${
                        finding.status === 'resolved'
                          ? 'bg-green-100 text-green-800'
                          : finding.status === 'in_progress'
                          ? 'bg-blue-100 text-blue-800'
                          : 'bg-gray-100 text-gray-800'
                      }`}
                    >
                      {finding.status.replace('_', ' ')}
                    </span>
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap text-right text-sm">
                    <button
                      onClick={() => toggleExpand(finding.id)}
                      className="text-gray-400 hover:text-gray-600"
                    >
                      {expandedId === finding.id ? (
                        <ChevronUp className="w-5 h-5" />
                      ) : (
                        <ChevronDown className="w-5 h-5" />
                      )}
                    </button>
                  </td>
                </tr>

                {/* Expanded Details Row */}
                {expandedId === finding.id && (
                  <tr>
                    <td colSpan={7} className="px-4 py-4 bg-gray-50">
                      <div className="space-y-4">
                        {/* Description */}
                        {finding.description && (
                          <div>
                            <h4 className="text-sm font-semibold text-gray-700 mb-2">
                              Description
                            </h4>
                            <p className="text-sm text-gray-600">{finding.description}</p>
                          </div>
                        )}

                        {/* Evidence */}
                        {finding.evidence && (
                          <div>
                            <h4 className="text-sm font-semibold text-gray-700 mb-2">Evidence</h4>
                            <pre className="text-xs bg-white p-3 rounded border border-gray-200 overflow-x-auto">
                              {finding.evidence}
                            </pre>
                          </div>
                        )}

                        {/* Remediation */}
                        {finding.remediation_guidance && (
                          <div>
                            <h4 className="text-sm font-semibold text-gray-700 mb-2 flex items-center gap-2">
                              <AlertCircle className="w-4 h-4 text-blue-600" />
                              Remediation Guidance
                            </h4>
                            <div className="text-sm text-gray-600 bg-blue-50 p-3 rounded border border-blue-200">
                              {finding.remediation_guidance}
                            </div>
                            {finding.effort_hours && (
                              <p className="text-xs text-gray-500 mt-2">
                                Estimated effort: {finding.effort_hours} hours
                              </p>
                            )}
                          </div>
                        )}

                        {/* Actions */}
                        <div className="flex gap-2 pt-2">
                          <button
                            onClick={() => onSelectFinding(finding)}
                            className="px-3 py-1 text-sm bg-blue-600 text-white rounded hover:bg-blue-700"
                          >
                            View Full Details
                          </button>
                          {!finding.jira_ticket_url && (
                            <button
                              onClick={() => onCreateTicket([finding.id])}
                              className="px-3 py-1 text-sm bg-gray-600 text-white rounded hover:bg-gray-700"
                            >
                              Create Jira Ticket
                            </button>
                          )}
                        </div>
                      </div>
                    </td>
                  </tr>
                )}
              </React.Fragment>
            ))}
          </tbody>
        </table>
      </div>

      {/* Empty State */}
      {findings.length === 0 && (
        <div className="text-center py-12">
          <AlertCircle className="w-12 h-12 text-gray-400 mx-auto mb-3" />
          <p className="text-gray-500">No findings to display</p>
        </div>
      )}
    </div>
  );
};

export default FindingsTable;