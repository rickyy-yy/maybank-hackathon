import React from 'react';
import { FileText, Clock, CheckCircle, XCircle, AlertTriangle } from 'lucide-react';
import { useScans } from '../../hooks/useScans';
import { format } from 'date-fns';

const ScanList: React.FC = () => {
  const { data, isLoading, error } = useScans();

  if (isLoading) {
    return (
      <div className="card">
        <div className="text-center py-8">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto"></div>
          <p className="mt-4 text-gray-600">Loading scans...</p>
        </div>
      </div>
    );
  }

  if (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    return (
      <div className="card">
        <div className="text-center py-8">
          <XCircle className="w-12 h-12 mx-auto mb-4 text-red-600" />
          <h3 className="text-lg font-semibold text-red-600 mb-2">Error Loading Scans</h3>
          <p className="text-red-600 mb-4">{errorMessage}</p>
          
          <div className="bg-red-50 border border-red-200 rounded p-4 text-left max-w-2xl mx-auto">
            <p className="text-sm font-semibold text-red-800 mb-2">Troubleshooting:</p>
            <ul className="text-sm text-red-700 space-y-1 list-disc list-inside">
              <li>Check if backend is running: <code className="bg-red-100 px-1 rounded">docker-compose ps</code></li>
              <li>Check backend logs: <code className="bg-red-100 px-1 rounded">docker-compose logs backend</code></li>
              <li>Verify API is accessible: <code className="bg-red-100 px-1 rounded">curl http://localhost:8000/api/v1/health</code></li>
              <li>Check browser console for detailed error messages</li>
            </ul>
          </div>
          
          <button
            onClick={() => window.location.reload()}
            className="mt-4 btn-primary"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  const scans = data?.scans || [];

  if (scans.length === 0) {
    return (
      <div className="card">
        <div className="text-center py-12">
          <FileText className="w-16 h-16 text-gray-400 mx-auto mb-4" />
          <h3 className="text-lg font-semibold text-gray-700 mb-2">No scans yet</h3>
          <p className="text-gray-500 mb-4">Upload your first vulnerability scan to get started</p>
          <button
            onClick={() => {
              const uploadTab = document.querySelector('[data-tab="upload"]') as HTMLButtonElement;
              if (uploadTab) uploadTab.click();
            }}
            className="btn-primary"
          >
            Upload a Scan
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {scans.map((scan) => (
        <div key={scan.id} className="card hover:shadow-lg transition-shadow">
          <div className="flex items-start justify-between">
            <div className="flex items-start gap-4 flex-1">
              <div className="p-3 bg-blue-100 rounded-lg">
                <FileText className="w-6 h-6 text-blue-600" />
              </div>
              
              <div className="flex-1">
                <h3 className="text-lg font-semibold text-gray-900 mb-1">
                  {scan.filename}
                </h3>
                <div className="flex items-center gap-4 text-sm text-gray-600 mb-3">
                  <span className="flex items-center gap-1">
                    <Clock className="w-4 h-4" />
                    {format(new Date(scan.upload_date), 'MMM d, yyyy HH:mm')}
                  </span>
                  <span className="px-2 py-1 bg-gray-100 rounded text-xs">
                    {scan.source_tool.toUpperCase()}
                  </span>
                </div>

                {scan.processed ? (
                  <div className="flex items-center gap-6">
                    <div className="flex items-center gap-2">
                      <CheckCircle className="w-5 h-5 text-green-600" />
                      <span className="text-sm font-medium text-green-700">Processed</span>
                    </div>
                    <div className="flex gap-4 text-sm">
                      {scan.critical_count > 0 && (
                        <span className="text-red-600 font-semibold">
                          {scan.critical_count} Critical
                        </span>
                      )}
                      {scan.high_count > 0 && (
                        <span className="text-orange-600 font-semibold">
                          {scan.high_count} High
                        </span>
                      )}
                      {scan.medium_count > 0 && (
                        <span className="text-yellow-600 font-semibold">
                          {scan.medium_count} Medium
                        </span>
                      )}
                      <span className="text-gray-600">
                        {scan.total_findings} Total
                      </span>
                    </div>
                  </div>
                ) : scan.processing_error ? (
                  <div className="flex items-center gap-2">
                    <AlertTriangle className="w-5 h-5 text-red-600" />
                    <span className="text-sm text-red-600">Processing failed: {scan.processing_error}</span>
                  </div>
                ) : (
                  <div className="flex items-center gap-2">
                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-blue-600"></div>
                    <span className="text-sm text-blue-600">Processing...</span>
                  </div>
                )}
              </div>
            </div>

            <button
              onClick={() => (window.location.href = `/findings?scan_id=${scan.id}`)}
              className="btn-primary"
              disabled={!scan.processed}
            >
              View Findings
            </button>
          </div>
        </div>
      ))}
    </div>
  );
};

export default ScanList;