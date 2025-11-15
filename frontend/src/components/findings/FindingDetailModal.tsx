import React from 'react';
import { X, AlertCircle, Shield, Globe, Server, Code, ExternalLink, Calendar, TrendingUp } from 'lucide-react';

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

interface FindingDetailModalProps {
  finding: Finding;
  onClose: () => void;
  onCreateTicket: (findingIds: string[]) => void;
}

const FindingDetailModal: React.FC<FindingDetailModalProps> = ({ finding, onClose, onCreateTicket }) => {
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

  const linkifyText = (text: string) => {
    if (!text) return null;
    const urlRegex = /(https?:\/\/[^\s]+)/g;
    const parts = text.split(urlRegex);
    
    return parts.map((part, index) => {
      if (part.match(urlRegex)) {
        return (
          
            key={index}
            href={part}
            target="_blank"
            rel="noopener noreferrer"
            className="text-blue-600 hover:text-blue-800 underline inline-flex items-center gap-1"
          >
            {part.length > 80 ? part.substring(0, 80) + '...' : part}
            <ExternalLink className="w-3 h-3" />
          </a>
        );
      }
      return <span key={index}>{part}</span>;
    });
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-lg shadow-2xl max-w-6xl w-full max-h-[90vh] overflow-hidden flex flex-col">
        {/* Header */}
        <div className="bg-gradient-to-r from-blue-600 to-indigo-600 text-white p-6 flex items-start justify-between">
          <div className="flex-1">
            <div className="flex items-center gap-3 mb-2">
              <span className={`px-3 py-1 text-xs font-bold rounded-full border-2 ${getSeverityColor(finding.severity)} bg-white`}>
                {finding.severity}
              </span>
              {finding.cvss_score && (
                <span className="bg-white bg-opacity-20 px-3 py-1 rounded-full text-sm font-semibold">
                  CVSS: {finding.cvss_score.toFixed(1)}
                </span>
              )}
              {finding.priority_rank && (
                <span className="bg-white bg-opacity-20 px-3 py-1 rounded-full text-sm font-semibold">
                  Priority: #{finding.priority_rank}
                </span>
              )}
            </div>
            <h2 className="text-2xl font-bold mb-2">{finding.title}</h2>
            <div className="flex items-center gap-4 text-sm opacity-90">
              {finding.cve_id && <span>CVE: {finding.cve_id}</span>}
              {finding.cwe_id && <span>CWE: {finding.cwe_id}</span>}
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-white hover:bg-white hover:bg-opacity-20 rounded-full p-2 transition-colors"
          >
            <X className="w-6 h-6" />
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* Asset Information */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="bg-gray-50 rounded-lg p-4 border border-gray-200">
              <div className="flex items-center gap-2 mb-2">
                <Server className="w-5 h-5 text-blue-600" />
                <h3 className="font-semibold text-gray-900">Affected Asset</h3>
              </div>
              <p className="text-sm font-mono text-gray-700">{finding.affected_asset}</p>
              {finding.asset_hostname && (
                <p className="text-xs text-gray-600 mt-1">Hostname: {finding.asset_hostname}</p>
              )}
            </div>

            <div className="bg-gray-50 rounded-lg p-4 border border-gray-200">
              <div className="flex items-center gap-2 mb-2">
                <Globe className="w-5 h-5 text-blue-600" />
                <h3 className="font-semibold text-gray-900">Network Details</h3>
              </div>
              {finding.port && (
                <p className="text-sm text-gray-700">
                  Port: <span className="font-mono">{finding.port}/{finding.protocol}</span>
                </p>
              )}
              {finding.service && (
                <p className="text-sm text-gray-700 mt-1">Service: {finding.service}</p>
              )}
            </div>
          </div>

          {/* Risk Information */}
          <div className="bg-gradient-to-r from-orange-50 to-red-50 rounded-lg p-4 border border-orange-200">
            <div className="flex items-center gap-2 mb-3">
              <TrendingUp className="w-5 h-5 text-orange-600" />
              <h3 className="font-semibold text-gray-900">Risk Assessment</h3>
            </div>
            <div className="grid grid-cols-3 gap-4">
              <div>
                <p className="text-xs text-gray-600">Risk Score</p>
                <p className="text-2xl font-bold text-orange-600">{finding.risk_score || 'N/A'}</p>
              </div>
              <div>
                <p className="text-xs text-gray-600">Priority Rank</p>
                <p className="text-2xl font-bold text-orange-600">#{finding.priority_rank || 'N/A'}</p>
              </div>
              <div>
                <p className="text-xs text-gray-600">Status</p>
                <p className="text-sm font-semibold text-gray-700 mt-1 capitalize">
                  {finding.status.replace('_', ' ')}
                </p>
              </div>
            </div>
          </div>

          {/* Description */}
          {finding.description && (
            <div>
              <div className="flex items-center gap-2 mb-3">
                <AlertCircle className="w-5 h-5 text-blue-600" />
                <h3 className="font-semibold text-gray-900">Description</h3>
              </div>
              <div className="bg-white rounded-lg p-4 border border-gray-200">
                <p className="text-sm text-gray-700 leading-relaxed">{linkifyText(finding.description)}</p>
              </div>
            </div>
          )}

          {/* Evidence */}
          {finding.evidence && (
            <div>
              <div className="flex items-center gap-2 mb-3">
                <Code className="w-5 h-5 text-blue-600" />
                <h3 className="font-semibold text-gray-900">Evidence</h3>
              </div>
              <pre className="bg-gray-900 text-gray-100 p-4 rounded-lg overflow-x-auto text-xs font-mono border border-gray-700 max-h-64">
                {finding.evidence}
              </pre>
            </div>
          )}

          {/* CVSS Vector */}
          {finding.cvss_vector && (
            <div>
              <div className="flex items-center gap-2 mb-3">
                <Shield className="w-5 h-5 text-blue-600" />
                <h3 className="font-semibold text-gray-900">CVSS Vector</h3>
              </div>
              <div className="bg-white rounded-lg p-4 border border-gray-200">
                <code className="text-sm font-mono text-gray-700">{finding.cvss_vector}</code>
              </div>
            </div>
          )}

          {/* Timeline */}
          <div>
            <div className="flex items-center gap-2 mb-3">
              <Calendar className="w-5 h-5 text-blue-600" />
              <h3 className="font-semibold text-gray-900">Timeline</h3>
            </div>
            <div className="bg-white rounded-lg p-4 border border-gray-200">
              <div className="flex items-center justify-between text-sm">
                <div>
                  <p className="text-gray-600">Detected</p>
                  <p className="font-semibold text-gray-900">
                    {new Date(finding.detected_date).toLocaleString()}
                  </p>
                </div>
                {finding.resolved_date && (
                  <div className="text-right">
                    <p className="text-gray-600">Resolved</p>
                    <p className="font-semibold text-gray-900">
                      {new Date(finding.resolved_date).toLocaleString()}
                    </p>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* External References */}
          <div>
            <h3 className="font-semibold text-gray-900 mb-3">External References</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {finding.cve_id && (
                
                  href={`https://nvd.nist.gov/vuln/detail/${finding.cve_id}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-2 bg-white p-3 rounded-lg border border-gray-200 hover:border-blue-400 hover:bg-blue-50 transition-colors"
                >
                  <ExternalLink className="w-4 h-4 text-blue-600" />
                  <span className="text-sm font-medium text-gray-700">View on NVD Database</span>
                </a>
              )}
              {finding.cwe_id && (
                
                  href={`https://cwe.mitre.org/data/definitions/${finding.cwe_id.replace('CWE-', '')}.html`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-2 bg-white p-3 rounded-lg border border-gray-200 hover:border-blue-400 hover:bg-blue-50 transition-colors"
                >
                  <ExternalLink className="w-4 h-4 text-blue-600" />
                  <span className="text-sm font-medium text-gray-700">View CWE Details</span>
                </a>
              )}
            </div>
          </div>
        </div>

        {/* Footer Actions */}
        <div className="bg-gray-50 p-6 border-t border-gray-200 flex items-center justify-between">
          <div className="text-sm text-gray-600">
            Finding ID: <code className="bg-gray-200 px-2 py-1 rounded font-mono text-xs">{finding.id}</code>
          </div>
          <div className="flex gap-3">
            {finding.jira_ticket_url ? (
              
                href={finding.jira_ticket_url}
                target="_blank"
                rel="noopener noreferrer"
                className="px-6 py-2 bg-green-600 text-white rounded-md hover:bg-green-700 font-medium inline-flex items-center gap-2"
              >
                View Jira Ticket
                <ExternalLink className="w-4 h-4" />
              </a>
            ) : (
              <button
                onClick={() => {
                  onCreateTicket([finding.id]);
                  onClose();
                }}
                className="px-6 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 font-medium"
              >
                Create Jira Ticket
              </button>
            )}
            <button
              onClick={onClose}
              className="px-6 py-2 bg-gray-300 text-gray-700 rounded-md hover:bg-gray-400 font-medium"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default FindingDetailModal;