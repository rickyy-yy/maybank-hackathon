import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { BarChart3, TrendingUp, Shield, AlertTriangle } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import api from '../services/api';

const AnalyticsPage: React.FC = () => {
  const { data: summary, isLoading } = useQuery({
    queryKey: ['analytics', 'summary'],
    queryFn: async () => {
      const response = await api.get('/api/v1/analytics/summary');
      return response.data;
    },
  });

  const { data: scans } = useQuery({
    queryKey: ['scans'],
    queryFn: async () => {
      const response = await api.get('/api/v1/scans');
      return response.data;
    },
  });

  if (isLoading) {
    return (
      <div className="card">
        <div className="text-center py-12">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
          <p className="text-gray-600">Loading analytics...</p>
        </div>
      </div>
    );
  }

  const severityData = [
    { name: 'Critical', value: summary?.by_severity?.CRITICAL || 0, color: '#dc2626' },
    { name: 'High', value: summary?.by_severity?.HIGH || 0, color: '#ea580c' },
    { name: 'Medium', value: summary?.by_severity?.MEDIUM || 0, color: '#ca8a04' },
    { name: 'Low', value: summary?.by_severity?.LOW || 0, color: '#16a34a' },
    { name: 'Info', value: summary?.by_severity?.INFO || 0, color: '#2563eb' },
  ];

  const scanHistory = scans?.scans?.slice(0, 10).reverse().map((scan: any) => ({
    name: new Date(scan.upload_date).toLocaleDateString(),
    Critical: scan.critical_count,
    High: scan.high_count,
    Medium: scan.medium_count,
    Low: scan.low_count,
  })) || [];

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-3xl font-bold text-gray-900 mb-2">Analytics Dashboard</h1>
        <p className="text-gray-600">Security posture overview and trends</p>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-6">
        <div className="card bg-gradient-to-br from-blue-50 to-blue-100">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-blue-600">Total Findings</p>
              <p className="text-3xl font-bold text-blue-900">{summary?.total_findings || 0}</p>
            </div>
            <Shield className="w-12 h-12 text-blue-600 opacity-50" />
          </div>
        </div>

        <div className="card bg-gradient-to-br from-red-50 to-red-100">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-red-600">Critical</p>
              <p className="text-3xl font-bold text-red-900">{summary?.by_severity?.CRITICAL || 0}</p>
            </div>
            <AlertTriangle className="w-12 h-12 text-red-600 opacity-50" />
          </div>
        </div>

        <div className="card bg-gradient-to-br from-orange-50 to-orange-100">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-orange-600">High</p>
              <p className="text-3xl font-bold text-orange-900">{summary?.by_severity?.HIGH || 0}</p>
            </div>
            <TrendingUp className="w-12 h-12 text-orange-600 opacity-50" />
          </div>
        </div>

        <div className="card bg-gradient-to-br from-purple-50 to-purple-100">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-purple-600">Total Scans</p>
              <p className="text-3xl font-bold text-purple-900">{scans?.total || 0}</p>
            </div>
            <BarChart3 className="w-12 h-12 text-purple-600 opacity-50" />
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Severity Distribution */}
        <div className="card">
          <h3 className="text-lg font-semibold mb-4">Severity Distribution</h3>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={severityData}
                dataKey="value"
                nameKey="name"
                cx="50%"
                cy="50%"
                outerRadius={100}
                label
              >
                {severityData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip />
              <Legend />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* Scan History Trend */}
        <div className="card">
          <h3 className="text-lg font-semibold mb-4">Recent Scan Trends</h3>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={scanHistory}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="name" />
              <YAxis />
              <Tooltip />
              <Legend />
              <Bar dataKey="Critical" fill="#dc2626" />
              <Bar dataKey="High" fill="#ea580c" />
              <Bar dataKey="Medium" fill="#ca8a04" />
              <Bar dataKey="Low" fill="#16a34a" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
};

export default AnalyticsPage;