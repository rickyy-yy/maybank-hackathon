import React, { useState } from 'react';
import { ChevronDown, ChevronUp, ExternalLink, AlertCircle, CheckCircle2, Clock, Wrench } from 'lucide-react';
import FindingDetailModal from './FindingDetailModal';
import JiraTicketModal from './JiraTicketModal';

interface Finding {
  id: string;
  source_scan_id: string;
  title: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  cvss_score?: number;
  cvss_vector?: string;
  cve_id?: string;
  cwe_id?: string;
  risk_score: number;
  priority_rank: number;
  affected_asset: string;
  asset_hostname?: string;
  port?: number;
  protocol?: string;
  service?: string;
  evidence?: string;
  remediation_guidance?: string;
  effort_hours?: number;
  status: 'open' | 'in_progress' | 'resolved' | 'false_positive';
  jira_ticket_key?: string;
  jira_ticket_url?: string;
  detected_date: string;
  resolved_date?: string;
}

interface FindingsTableProps {
  findings: Finding[];
  onSelectFinding: (finding: Finding) => void;
  onCreateTicket: (findingIds: string[]) => void;
}

const RemediationGuidanceDisplay: React.FC<{ guidance: string; effortHours?: number }> = ({ 
  guidance, 
  effortHours 
}) => {
  const parseGuidance = (text: string) => {
    const sections: { title: string; content: string; type: string }[] = [];
    
    if (!text || typeof text !== 'string') {
      return sections;
    }
    
    const parts = text.split(/(?=^#{1,3}\s)/m);
    
    parts.forEach(part => {
      const trimmed = part.trim();
      if (!trimmed) return;
      
      const headerMatch = trimmed.match(/^#{1,3}\s+(.+?)$/m);
      if (headerMatch) {
        const title = headerMatch[1].replace(/\*\*/g, '').trim();
        const content = trimmed.substring(headerMatch[0].length).trim();
        
        let type = 'info';
        if (title.includes('Remediation') || title.includes('Steps') || title.includes('Actions')) {
          type = 'steps';
        } else if (title.includes('Code') || title.includes('Example')) {
          type = 'code';
        } else if (title.includes('Reference') || title.includes('Resource')) {
          type = 'links';
        } else if (title.includes('Overview') || title.includes('Issue')) {
          type = 'description';
        } else if (title.includes('Security') || title.includes('Advisory')) {
          type = 'advisory';
        }
        
        sections.push({ title, content, type });
      } else {
        sections.push({ title: '', content: trimmed, type: 'text' });
      }
    });
    
    return sections;
  };

  const linkifyText = (text: string) => {
    if (!text) return text;

    const urlRegex = /(https?:\/\/[^\s]+)/g;
    const parts = text.split(urlRegex);

    return parts.map((part, index) => {
      if (part.match(urlRegex)) {
        return (
          <a
            key={index}
            href={part}
            target="_blank"
            rel="noopener noreferrer"
            className="text-blue-600 hover:text-blue-800 underline inline-flex items-center gap-1"
          >
            {part.length > 60 ? part.substring(0, 60) + '...' : part}
            <ExternalLink className="w-3 h-3" />
          </a>
        );
      }
      return <span key={index}>{part}</span>;
    });
  };

  const formatContent = (content: string, type: string) => {
    if (!content || typeof content !== 'string') {
      return null;
    }
    
    const lines = content.split('\n').filter(line => line.trim());
    
    if (type === 'steps') {
      return (
        <ol className="list-decimal list-inside space-y-2 text-sm">
          {lines.map((line, index) => {
            const cleaned = line.replace(/^\d+\.\s*/, '').replace(/\*\*/g, '').trim();
            if (!cleaned) return null;
            return (
              <li key={index} className="text-gray-700 leading-relaxed">
                {linkifyText(cleaned)}
              </li>
            );
          })}
        </ol>
      );
    } else if (type === 'links') {
      return (
        <ul className="space-y-2 text-sm">
          {lines.map((line, index) => {
            const cleaned = line.replace(/^[-*]\s*/, '').replace(/\*\*/g, '').trim();
            if (!cleaned) return null;
            return (
              <li key={index} className="text-gray-700 flex items-start gap-2">
                <ExternalLink className="w-4 h-4 text-blue-500 flex-shrink-0 mt-0.5" />
                <span>{linkifyText(cleaned)}</span>
              </li>
            );
          })}
        </ul>
      );
    } else if (type === 'code') {
      return (
        <pre className="bg-gray-900 text-gray-100 p-4 rounded-lg overflow-x-auto text-xs font-mono">
          <code>{content.replace(/```/g, '').trim()}</code>
        </pre>
      );
    } else {
      return (
        <div className="text-sm text-gray-700 space-y-2">
          {lines.map((line, index) => {
            const cleaned = line.replace(/^[-*]\s*/, '').replace(/\*\*/g, '').trim();
            if (!cleaned) return null;
            return <p key={index} className="leading-relaxed">{linkifyText(cleaned)}</p>;
          })}
        </div>
      );
    }
  };

  const sections = parseGuidance(guidance);

  if (!guidance || sections.length === 0) {
    return (
      <div className="bg-blue-50 p-4 rounded-lg border border-blue-200">
        <p className="text-sm text-gray-600">No remediation guidance available for this finding.</p>
      </div>
    );
  }

  return (
    <div className="space-y-6 bg-gradient-to-br from-blue-50 to-indigo-50 p-6 rounded-lg border border-blue-200">
      <div className="flex items-center justify-between border-b border-blue-200 pb-4">
        <div className="flex items-center gap-3">
          <div className="bg-blue-600 p-2 rounded-lg">
            <Wrench className="w-5 h-5 text-white" />
          </div>
          <div>
            <h3 className="text-lg font-bold text-gray-900">Remediation Guidance</h3>
            <p className="text-sm text-gray-600">Step-by-step instructions to fix this vulnerability</p>
          </div>
        </div>
        {effortHours && (
          <div className="flex items-center gap-2 bg-white px-4 py-2 rounded-lg border border-blue-200">
            <Clock className="w-4 h-4 text-blue-600" />
            <div>
              <div className="text-xs text-gray-600">Estimated Effort</div>
              <div className="text-sm font-bold text-gray-900">{effortHours} hours</div>
            </div>
          </div>
        )}
      </div>

      {sections.map((section, index) => {
        if (!section.content && !section.title) return null;
        
        const getSectionIcon = (type: string) => {
          switch (type) {
            case 'steps':
              return <CheckCircle2 className="w-5 h-5 text-green-600" />;
            case 'advisory':
              return <AlertCircle className="w-5 h-5 text-orange-600" />;
            case 'links':
              return <ExternalLink className="w-5 h-5 text-blue-600" />;
            default:
              return null;
          }
        };

        const getSectionColor = (type: string) => {
          switch (type) {
            case 'steps':
              return 'bg-green-50 border-green-200';
            case 'advisory':
              return 'bg-orange-50 border-orange-200';
            case 'links':
              return 'bg-blue-50 border-blue-200';
            case 'description':
              return 'bg-gray-50 border-gray-200';
            default:
              return 'bg-white border-gray-200';
          }
        };

        return (
          <div key={index} className={`rounded-lg border ${getSectionColor(section.type)} p-4`}>
            {section.title && (
              <div className="flex items-center gap-2 mb-3">
                {getSectionIcon(section.type)}
                <h4 className="font-semibold text-gray-900">{section.title}</h4>
              </div>
            )}
            {section.content && formatContent(section.content, section.type)}
          </div>
        );
      })}
    </div>
  );
};

const FindingsTable: React.FC<FindingsTableProps> = ({
  findings,
  onSelectFinding,
  onCreateTicket,
}) => {
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [detailModalFinding, setDetailModalFinding] = useState<Finding | null>(null);
  const [jiraModalData, setJiraModalData] = useState<{ findingIds: string[]; titles: string[] } | null>(null);

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

  const handleViewDetails = (finding: Finding) => {
    setDetailModalFinding(finding);
  };

  const handleCreateJiraTickets = (findingIds: string[]) => {
    const titles = findingIds.map(id => {
      const finding = findings.find(f => f.id === id);
      return finding ? finding.title : 'Unknown';
    });
    setJiraModalData({ findingIds, titles });
  };

  const handleJiraSuccess = () => {
    window.location.reload();
  };

  return (
    <>
      {detailModalFinding && (
        <FindingDetailModal
          finding={detailModalFinding}
          onClose={() => setDetailModalFinding(null)}
          onCreateTicket={handleCreateJiraTickets}
        />
      )}

      {jiraModalData && (
        <JiraTicketModal
          findingIds={jiraModalData.findingIds}
          findingTitles={jiraModalData.titles}
          onClose={() => setJiraModalData(null)}
          onSuccess={handleJiraSuccess}
        />
      )}

      <div className="bg-white rounded-lg shadow">
        {selectedIds.size > 0 && (
          <div className="bg-blue-50 px-4 py-3 border-b border-blue-200 flex items-center justify-between">
            <span className="text-sm text-blue-800">
              {selectedIds.size} finding{selectedIds.size > 1 ? 's' : ''} selected
            </span>
            <button
              onClick={() => handleCreateJiraTickets(Array.from(selectedIds))}
              className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 text-sm font-medium"
            >
              Create Jira Tickets
            </button>
          </div>
        )}

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
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Severity</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Title</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Affected Asset</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">CVSS</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
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
                      <span className={`px-2 py-1 text-xs font-semibold rounded-full border ${getSeverityColor(finding.severity)}`}>
                        {finding.severity}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-900 max-w-md">
                      <div className="truncate font-medium">{finding.title}</div>
                      {finding.cve_id && <span className="text-xs text-gray-500">({finding.cve_id})</span>}
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-700">
                      <div className="flex flex-col">
                        <span className="font-mono text-xs">{finding.affected_asset}</span>
                        {finding.port && <span className="text-xs text-gray-500">Port {finding.port}/{finding.protocol}</span>}
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
                      <span className={`px-2 py-1 text-xs rounded ${
                        finding.status === 'resolved'
                        ? 'bg-green-100 text-green-800'
                          : finding.status === 'in_progress'
                        ? 'bg-blue-100 text-blue-800'
                          : 'bg-gray-100 text-gray-800'
                      }`}>
                        {finding.status.replace('_', ' ')}
                      </span>
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap text-right text-sm">
                      <button
                        onClick={() => toggleExpand(finding.id)}
                        className="text-gray-400 hover:text-gray-600 transition-colors"
                      >
                        {expandedId === finding.id ? (
                          <ChevronUp className="w-5 h-5" />
                        ) : (
                          <ChevronDown className="w-5 h-5" />
                        )}
                      </button>
                    </td>
                  </tr>

                  {expandedId === finding.id && (
                    <tr>
                      <td colSpan={7} className="px-4 py-6 bg-gray-50">
                        <div className="space-y-6 max-w-6xl">
                          {finding.description && (
                            <div>
                              <h4 className="text-sm font-semibold text-gray-700 mb-2 flex items-center gap-2">
                                <AlertCircle className="w-4 h-4 text-orange-600" />
                                Description
                              </h4>
                              <p className="text-sm text-gray-600 bg-white p-4 rounded-lg border border-gray-200">
                                {finding.description}
                              </p>
                            </div>
                          )}

                          {finding.evidence && (
                            <div>
                              <h4 className="text-sm font-semibold text-gray-700 mb-2">Evidence</h4>
                              <pre className="text-xs bg-gray-900 text-gray-100 p-4 rounded-lg overflow-x-auto border border-gray-700">
                                {finding.evidence}
                              </pre>
                            </div>
                          )}

                          {finding.remediation_guidance && (
                            <RemediationGuidanceDisplay
                              guidance={finding.remediation_guidance}
                              effortHours={finding.effort_hours}
                            />
                          )}

                          <div className="flex gap-3 pt-2">
                            <button
                              onClick={() => handleViewDetails(finding)}
                              className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 font-medium text-sm"
                            >
                              View Full Details
                            </button>
                            {!finding.jira_ticket_url && (
                              <button
                                onClick={() => handleCreateJiraTickets([finding.id])}
                                className="px-4 py-2 bg-gray-600 text-white rounded-md hover:bg-gray-700 font-medium text-sm"
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

        {findings.length === 0 && (
          <div className="text-center py-12">
            <AlertCircle className="w-12 h-12 text-gray-400 mx-auto mb-3" />
            <p className="text-gray-500">No findings to display</p>
          </div>
        )}
      </div>
    </>
  );
};

export default FindingsTable;