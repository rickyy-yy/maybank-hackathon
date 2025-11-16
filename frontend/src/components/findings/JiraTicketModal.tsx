import React, { useState } from 'react';
import { X, CheckCircle, AlertCircle, Loader2, ExternalLink } from 'lucide-react';

interface JiraTicketModalProps {
  findingIds: string[];
  findingTitles: string[];
  onClose: () => void;
  onSuccess: () => void;
}

const JiraTicketModal: React.FC<JiraTicketModalProps> = ({ 
  findingIds, 
  findingTitles,
  onClose, 
  onSuccess 
}) => {
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);
  const [createdTickets, setCreatedTickets] = useState<Array<{ key: string; url: string }>>([]);

  const [formData, setFormData] = useState({
    projectKey: 'SEC',
    issueType: 'Bug',
    priority: 'High',
    assignee: '',
    labels: 'security,vulnerability',
    description: '',
  });

  const handleSubmit = async () => {
    setIsSubmitting(true);
    setError(null);

    try {
      const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';
      const url = `${API_URL}/api/v1/integrations/jira/create-tickets`;
      
      const payload = {
        finding_ids: findingIds,
        project_key: formData.projectKey,
        issue_type: formData.issueType,
        priority: formData.priority,
        assignee: formData.assignee || null,
        labels: formData.labels.split(',').map(l => l.trim()).filter(Boolean),
        additional_description: formData.description,
      };
      
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || 'Failed to create Jira tickets');
      }

      setCreatedTickets(data.tickets || []);
      setSuccess(true);
      
      setTimeout(() => {
        onSuccess();
      }, 2000);

    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setIsSubmitting(false);
    }
  };

  if (success) {
    return (
      <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
        <div className="bg-white rounded-lg shadow-2xl max-w-2xl w-full p-8">
          <div className="text-center">
            <div className="bg-green-100 rounded-full w-16 h-16 flex items-center justify-center mx-auto mb-4">
              <CheckCircle className="w-10 h-10 text-green-600" />
            </div>
            <h2 className="text-2xl font-bold text-gray-900 mb-2">Tickets Created Successfully!</h2>
            <p className="text-gray-600 mb-6">
              {createdTickets.length} Jira {createdTickets.length === 1 ? 'ticket has' : 'tickets have'} been created
            </p>
            
            <div className="space-y-3 mb-6">
              {createdTickets.map((ticket, index) => (
                <a
                  key={index}
                  href={ticket.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center justify-between bg-green-50 p-4 rounded-lg border border-green-200 hover:bg-green-100 transition-colors"
                >
                  <div className="flex items-center gap-3">
                    <span className="bg-green-600 text-white px-3 py-1 rounded font-mono text-sm font-bold">
                      {ticket.key}
                    </span>
                    <span className="text-sm text-gray-700">{findingTitles[index]}</span>
                  </div>
                  <ExternalLink className="w-4 h-4 text-green-600" />
                </a>
              ))}
            </div>

            <button
              onClick={onClose}
              className="px-6 py-2 bg-green-600 text-white rounded-md hover:bg-green-700 font-medium"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-lg shadow-2xl max-w-2xl w-full max-h-[90vh] overflow-hidden">
        <div className="bg-gradient-to-r from-blue-600 to-indigo-600 text-white p-6 flex items-center justify-between">
          <div>
            <h2 className="text-2xl font-bold">Create Jira Tickets</h2>
            <p className="text-sm opacity-90 mt-1">
              Creating {findingIds.length} {findingIds.length === 1 ? 'ticket' : 'tickets'} for selected findings
            </p>
          </div>
          <button
            onClick={onClose}
            className="text-white hover:bg-white hover:bg-opacity-20 rounded-full p-2 transition-colors"
            disabled={isSubmitting}
          >
            <X className="w-6 h-6" />
          </button>
        </div>

        <div className="p-6 space-y-6 overflow-y-auto max-h-[calc(90vh-200px)]">
          <div>
            <label className="block text-sm font-semibold text-gray-700 mb-2">
              Selected Findings ({findingIds.length})
            </label>
            <div className="bg-gray-50 rounded-lg p-4 border border-gray-200 max-h-32 overflow-y-auto">
              <ul className="text-sm text-gray-700 space-y-1">
                {findingTitles.map((title, index) => (
                  <li key={index} className="flex items-start gap-2">
                    <span className="text-blue-600 mt-1">•</span>
                    <span>{title}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>

          <div>
            <label htmlFor="projectKey" className="block text-sm font-semibold text-gray-700 mb-2">
              Project Key <span className="text-red-500">*</span>
            </label>
            <input
              type="text"
              id="projectKey"
              value={formData.projectKey}
              onChange={(e) => setFormData({ ...formData, projectKey: e.target.value })}
              className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              placeholder="e.g., SEC, VULN, INFOSEC"
              required
            />
            <p className="text-xs text-gray-500 mt-1">Enter your Jira project key</p>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label htmlFor="issueType" className="block text-sm font-semibold text-gray-700 mb-2">
                Issue Type <span className="text-red-500">*</span>
              </label>
              <select
                id="issueType"
                value={formData.issueType}
                onChange={(e) => setFormData({ ...formData, issueType: e.target.value })}
                className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                required
              >
                <option value="Bug">Bug</option>
                <option value="Task">Task</option>
                <option value="Story">Story</option>
                <option value="Security">Security</option>
              </select>
            </div>

            <div>
              <label htmlFor="priority" className="block text-sm font-semibold text-gray-700 mb-2">
                Priority <span className="text-red-500">*</span>
              </label>
              <select
                id="priority"
                value={formData.priority}
                onChange={(e) => setFormData({ ...formData, priority: e.target.value })}
                className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                required
              >
                <option value="Highest">Highest</option>
                <option value="High">High</option>
                <option value="Medium">Medium</option>
                <option value="Low">Low</option>
                <option value="Lowest">Lowest</option>
              </select>
            </div>
          </div>

          <div>
            <label htmlFor="assignee" className="block text-sm font-semibold text-gray-700 mb-2">
              Assignee
            </label>
            <input
              type="text"
              id="assignee"
              value={formData.assignee}
              onChange={(e) => setFormData({ ...formData, assignee: e.target.value })}
              className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              placeholder="e.g., john.doe@company.com (optional)"
            />
            <p className="text-xs text-gray-500 mt-1">Leave empty for unassigned</p>
          </div>

          <div>
            <label htmlFor="labels" className="block text-sm font-semibold text-gray-700 mb-2">
              Labels
            </label>
            <input
              type="text"
              id="labels"
              value={formData.labels}
              onChange={(e) => setFormData({ ...formData, labels: e.target.value })}
              className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              placeholder="e.g., security, vulnerability, critical"
            />
            <p className="text-xs text-gray-500 mt-1">Comma-separated labels</p>
          </div>

          <div>
            <label htmlFor="description" className="block text-sm font-semibold text-gray-700 mb-2">
              Additional Description
            </label>
            <textarea
              id="description"
              value={formData.description}
              onChange={(e) => setFormData({ ...formData, description: e.target.value })}
              rows={4}
              className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              placeholder="Add any additional context or instructions..."
            />
            <p className="text-xs text-gray-500 mt-1">
              This will be appended to the automatically generated ticket description
            </p>
          </div>

          {error && (
            <div className="bg-red-50 border border-red-200 rounded-lg p-4 flex items-start gap-3">
              <AlertCircle className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" />
              <div>
                <p className="font-semibold text-red-800">Error Creating Tickets</p>
                <p className="text-sm text-red-700 mt-1">{error}</p>
              </div>
            </div>
          )}
        </div>

        <div className="bg-gray-50 p-6 border-t border-gray-200 flex items-center justify-end gap-3">
          <button
            type="button"
            onClick={onClose}
            className="px-6 py-2 bg-gray-300 text-gray-700 rounded-md hover:bg-gray-400 font-medium"
            disabled={isSubmitting}
          >
            Cancel
          </button>
          <button
            onClick={handleSubmit}
            disabled={isSubmitting}
            className="px-6 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 font-medium disabled:bg-blue-400 disabled:cursor-not-allowed flex items-center gap-2"
          >
            {isSubmitting ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                Creating Tickets...
              </>
            ) : (
              `Create ${findingIds.length} ${findingIds.length === 1 ? 'Ticket' : 'Tickets'}`
            )}
          </button>
        </div>
      </div>
    </div>
  );
};

export default JiraTicketModal;