import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Save, Check, X, AlertCircle, Loader2 } from 'lucide-react';
import api from '../services/api';

interface JiraSettings {
  jira_url: string | null;
  jira_email: string | null;
  jira_api_token_set: boolean;
  jira_project_key: string | null;
  jira_enabled: boolean;
}

const SettingsPage: React.FC = () => {
  const queryClient = useQueryClient();
  const [testingConnection, setTestingConnection] = useState(false);
  const [testResult, setTestResult] = useState<{ success: boolean; message: string } | null>(null);

  const { data: jiraSettings, isLoading } = useQuery<JiraSettings>({
    queryKey: ['settings', 'jira'],
    queryFn: async () => {
      const response = await api.get('/api/v1/settings/jira');
      return response.data;
    },
  });

  const [formData, setFormData] = useState<{
    jira_url: string;
    jira_email: string;
    jira_api_token: string;
    jira_project_key: string;
    jira_enabled: boolean;
  }>({
    jira_url: '',
    jira_email: '',
    jira_api_token: '',
    jira_project_key: '',
    jira_enabled: false,
  });

  React.useEffect(() => {
    if (jiraSettings) {
      setFormData({
        jira_url: jiraSettings.jira_url || '',
        jira_email: jiraSettings.jira_email || '',
        jira_api_token: '', // Never populate from server
        jira_project_key: jiraSettings.jira_project_key || '',
        jira_enabled: jiraSettings.jira_enabled,
      });
    }
  }, [jiraSettings]);

  const saveMutation = useMutation({
    mutationFn: async (data: typeof formData) => {
      const response = await api.post('/api/v1/settings/jira', data);
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['settings', 'jira'] });
      setTestResult({ success: true, message: 'Settings saved successfully!' });
      setTimeout(() => setTestResult(null), 3000);
    },
    onError: (error: any) => {
      setTestResult({
        success: false,
        message: error.response?.data?.detail || 'Failed to save settings',
      });
    },
  });

  const handleTestConnection = async () => {
    setTestingConnection(true);
    setTestResult(null);

    try {
      const response = await api.post('/api/v1/settings/jira/test');
      setTestResult({
        success: response.data.success,
        message: response.data.message,
      });
    } catch (error: any) {
      setTestResult({
        success: false,
        message: error.response?.data?.detail || 'Connection test failed',
      });
    } finally {
      setTestingConnection(false);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    saveMutation.mutate(formData);
  };

  if (isLoading) {
    return (
      <div className="card">
        <div className="text-center py-12">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
          <p className="text-gray-600">Loading settings...</p>
        </div>
      </div>
    );
  }

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-3xl font-bold text-gray-900 mb-2">Settings</h1>
        <p className="text-gray-600">Configure integrations and system preferences</p>
      </div>

      {/* Jira Integration Settings */}
      <div className="card mb-6">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h2 className="text-xl font-semibold text-gray-900">Jira Integration</h2>
            <p className="text-sm text-gray-600 mt-1">
              Configure Jira to automatically create tickets for vulnerabilities
            </p>
          </div>
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={formData.jira_enabled}
              onChange={(e) => setFormData({ ...formData, jira_enabled: e.target.checked })}
              className="w-5 h-5 rounded border-gray-300 text-blue-600 focus:ring-blue-500"
            />
            <span className="text-sm font-medium text-gray-700">Enabled</span>
          </label>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Jira URL
            </label>
            <input
              type="url"
              value={formData.jira_url}
              onChange={(e) => setFormData({ ...formData, jira_url: e.target.value })}
              placeholder="https://your-domain.atlassian.net"
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
              required={formData.jira_enabled}
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Email Address
            </label>
            <input
              type="email"
              value={formData.jira_email}
              onChange={(e) => setFormData({ ...formData, jira_email: e.target.value })}
              placeholder="your-email@company.com"
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
              required={formData.jira_enabled}
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              API Token
              {jiraSettings?.jira_api_token_set && (
                <span className="ml-2 text-xs text-green-600">(configured)</span>
              )}
            </label>
            <input
              type="password"
              value={formData.jira_api_token}
              onChange={(e) => setFormData({ ...formData, jira_api_token: e.target.value })}
              placeholder={
                jiraSettings?.jira_api_token_set
                  ? 'Leave blank to keep current token'
                  : 'Enter your Jira API token'
              }
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
              required={formData.jira_enabled && !jiraSettings?.jira_api_token_set}
            />
            <p className="mt-1 text-xs text-gray-500">
              Generate an API token from{' '}
              <a
                href="https://id.atlassian.com/manage-profile/security/api-tokens"
                target="_blank"
                rel="noopener noreferrer"
                className="text-blue-600 hover:underline"
              >
                Atlassian Account Settings
              </a>
            </p>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Default Project Key
            </label>
            <input
              type="text"
              value={formData.jira_project_key}
              onChange={(e) => setFormData({ ...formData, jira_project_key: e.target.value })}
              placeholder="VULN"
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
            />
            <p className="mt-1 text-xs text-gray-500">
              Default project key for creating tickets (e.g., VULN, SEC, INFOSEC)
            </p>
          </div>

          {/* Status Messages */}
          {testResult && (
            <div
              className={`p-4 rounded-md flex items-center gap-3 ${
                testResult.success
                  ? 'bg-green-50 border border-green-200'
                  : 'bg-red-50 border border-red-200'
              }`}
            >
              {testResult.success ? (
                <Check className="w-5 h-5 text-green-600" />
              ) : (
                <X className="w-5 h-5 text-red-600" />
              )}
              <span
                className={`text-sm ${
                  testResult.success ? 'text-green-800' : 'text-red-800'
                }`}
              >
                {testResult.message}
              </span>
            </div>
          )}

          {/* Action Buttons */}
          <div className="flex gap-3 pt-4">
            <button
              type="submit"
              disabled={saveMutation.isPending}
              className="btn-primary flex items-center gap-2"
            >
              {saveMutation.isPending ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Saving...
                </>
              ) : (
                <>
                  <Save className="w-4 h-4" />
                  Save Settings
                </>
              )}
            </button>

            <button
              type="button"
              onClick={handleTestConnection}
              disabled={testingConnection || !formData.jira_enabled}
              className="btn-secondary flex items-center gap-2"
            >
              {testingConnection ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Testing...
                </>
              ) : (
                <>
                  <AlertCircle className="w-4 h-4" />
                  Test Connection
                </>
              )}
            </button>
          </div>
        </form>
      </div>

      {/* Instructions Card */}
      <div className="card bg-blue-50 border border-blue-200">
        <h3 className="text-lg font-semibold text-blue-900 mb-3">
          Setting up Jira Integration
        </h3>
        <ol className="space-y-2 text-sm text-blue-800">
          <li className="flex gap-2">
            <span className="font-semibold">1.</span>
            <span>
              Go to your Atlassian account settings and create an API token at{' '}
              <a
                href="https://id.atlassian.com/manage-profile/security/api-tokens"
                target="_blank"
                rel="noopener noreferrer"
                className="underline hover:text-blue-600"
              >
                this link
              </a>
            </span>
          </li>
          <li className="flex gap-2">
            <span className="font-semibold">2.</span>
            <span>Copy your Jira instance URL (e.g., https://yourcompany.atlassian.net)</span>
          </li>
          <li className="flex gap-2">
            <span className="font-semibold">3.</span>
            <span>Enter your Jira email address (the one you use to log in)</span>
          </li>
          <li className="flex gap-2">
            <span className="font-semibold">4.</span>
            <span>Paste the API token you generated in step 1</span>
          </li>
          <li className="flex gap-2">
            <span className="font-semibold">5.</span>
            <span>
              Enter your default project key (found in your Jira project settings)
            </span>
          </li>
          <li className="flex gap-2">
            <span className="font-semibold">6.</span>
            <span>Enable the integration and click "Test Connection" to verify</span>
          </li>
          <li className="flex gap-2">
            <span className="font-semibold">7.</span>
            <span>Once verified, click "Save Settings"</span>
          </li>
        </ol>
      </div>
    </div>
  );
};

export default SettingsPage;