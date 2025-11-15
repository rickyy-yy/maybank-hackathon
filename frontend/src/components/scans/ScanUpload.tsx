import React, { useState, useEffect } from 'react';
import { useDropzone } from 'react-dropzone';
import { Upload, FileText, AlertCircle, CheckCircle, Loader2 } from 'lucide-react';
import { useUploadScan, useScanStatus } from '../../hooks/useScans';
import { useNavigate } from 'react-router-dom';

const ScanUpload: React.FC = () => {
  const [uploadedScanId, setUploadedScanId] = useState<string | null>(null);
  const [sourceTool, setSourceTool] = useState('nessus');
  const navigate = useNavigate();
  
  const uploadMutation = useUploadScan();
  const { data: statusData, isError: statusError } = useScanStatus(
    uploadedScanId || '', 
    !!uploadedScanId
  );

  // Reset when status becomes completed or failed
  useEffect(() => {
    if (statusData?.status === 'completed' || statusData?.status === 'failed') {
      // Auto-clear after showing success for 2 seconds
      const timer = setTimeout(() => {
        setUploadedScanId(null);
      }, 5000);
      return () => clearTimeout(timer);
    }
  }, [statusData?.status]);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    accept: {
      'text/xml': ['.xml', '.nessus'],
      'application/json': ['.json'],
      'text/csv': ['.csv'],
    },
    maxFiles: 1,
    disabled: uploadMutation.isPending || (statusData?.status === 'processing'),
    onDrop: async (acceptedFiles) => {
      if (acceptedFiles.length > 0) {
        const file = acceptedFiles[0];
        try {
          const result = await uploadMutation.mutateAsync({ file, sourceTool });
          setUploadedScanId(result.scan_id);
        } catch (error) {
          console.error('Upload failed:', error);
        }
      }
    },
  });

  const getStatusIcon = () => {
    if (!statusData) return null;
    
    switch (statusData.status) {
      case 'processing':
        return <Loader2 className="w-5 h-5 text-blue-600 animate-spin" />;
      case 'completed':
        return <CheckCircle className="w-5 h-5 text-green-600" />;
      case 'failed':
        return <AlertCircle className="w-5 h-5 text-red-600" />;
      default:
        return null;
    }
  };

  const getStatusColor = () => {
    if (!statusData) return '';
    
    switch (statusData.status) {
      case 'processing':
        return 'border-blue-200 bg-blue-50';
      case 'completed':
        return 'border-green-200 bg-green-50';
      case 'failed':
        return 'border-red-200 bg-red-50';
      default:
        return '';
    }
  };

  return (
    <div className="space-y-6">
      {/* Upload Area */}
      <div className="card">
        <h2 className="text-xl font-semibold mb-4">Upload Vulnerability Scan</h2>
        
        {/* Source Tool Selection */}
        <div className="mb-4">
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Scanner Tool
          </label>
          <select
            value={sourceTool}
            onChange={(e) => setSourceTool(e.target.value)}
            disabled={uploadMutation.isPending || statusData?.status === 'processing'}
            className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500 disabled:bg-gray-100"
          >
            <option value="nessus">Nessus (.xml, .nessus)</option>
            <option value="burp">Burp Suite (.xml)</option>
            <option value="nmap">Nmap (.xml)</option>
          </select>
        </div>

        {/* Dropzone */}
        <div
          {...getRootProps()}
          className={`border-2 border-dashed rounded-lg p-12 text-center cursor-pointer transition-colors ${
            isDragActive
              ? 'border-blue-500 bg-blue-50'
              : uploadMutation.isPending || statusData?.status === 'processing'
              ? 'border-gray-200 bg-gray-50 cursor-not-allowed'
              : 'border-gray-300 hover:border-gray-400'
          }`}
        >
          <input {...getInputProps()} />
          <Upload className="w-12 h-12 text-gray-400 mx-auto mb-4" />
          {isDragActive ? (
            <p className="text-lg text-blue-600">Drop the file here...</p>
          ) : uploadMutation.isPending ? (
            <p className="text-lg text-gray-600">Uploading...</p>
          ) : statusData?.status === 'processing' ? (
            <p className="text-lg text-gray-600">Processing in progress...</p>
          ) : (
            <>
              <p className="text-lg text-gray-700 mb-2">
                Drag and drop a scan file here, or click to select
              </p>
              <p className="text-sm text-gray-500">
                Supported formats: XML, JSON, CSV (Max 100MB)
              </p>
            </>
          )}
        </div>

        {/* Upload Error */}
        {uploadMutation.isError && (
          <div className="mt-4 p-4 bg-red-50 border border-red-200 rounded-lg flex items-center gap-3">
            <AlertCircle className="w-5 h-5 text-red-600" />
            <span className="text-red-800">
              Upload failed: {(uploadMutation.error as Error).message}
            </span>
          </div>
        )}

        {/* Status Error */}
        {statusError && uploadedScanId && (
          <div className="mt-4 p-4 bg-yellow-50 border border-yellow-200 rounded-lg flex items-center gap-3">
            <AlertCircle className="w-5 h-5 text-yellow-600" />
            <span className="text-yellow-800">
              Unable to fetch scan status. Check "All Scans" tab for results.
            </span>
          </div>
        )}
      </div>

      {/* Processing Status */}
      {statusData && (
        <div className={`card border-2 ${getStatusColor()}`}>
          <div className="flex items-start gap-4">
            <div className="mt-1">{getStatusIcon()}</div>
            <div className="flex-1">
              <h3 className="text-lg font-semibold mb-2">
                {statusData.status === 'processing' && 'Processing Scan...'}
                {statusData.status === 'completed' && 'Scan Processing Complete'}
                {statusData.status === 'failed' && 'Processing Failed'}
              </h3>

              {statusData.status === 'completed' && statusData.statistics && (
                <div className="space-y-2">
                  <p className="text-gray-700">
                    Successfully processed{' '}
                    <span className="font-semibold">{statusData.total_findings}</span> findings
                  </p>
                  <div className="grid grid-cols-5 gap-4 mt-4">
                    <div className="text-center">
                      <div className="text-2xl font-bold text-red-600">
                        {statusData.statistics.critical}
                      </div>
                      <div className="text-xs text-gray-600">Critical</div>
                    </div>
                    <div className="text-center">
                      <div className="text-2xl font-bold text-orange-600">
                        {statusData.statistics.high}
                      </div>
                      <div className="text-xs text-gray-600">High</div>
                    </div>
                    <div className="text-center">
                      <div className="text-2xl font-bold text-yellow-600">
                        {statusData.statistics.medium}
                      </div>
                      <div className="text-xs text-gray-600">Medium</div>
                    </div>
                    <div className="text-center">
                      <div className="text-2xl font-bold text-green-600">
                        {statusData.statistics.low}
                      </div>
                      <div className="text-xs text-gray-600">Low</div>
                    </div>
                    <div className="text-center">
                      <div className="text-2xl font-bold text-blue-600">
                        {statusData.statistics.info}
                      </div>
                      <div className="text-xs text-gray-600">Info</div>
                    </div>
                  </div>
                  <div className="flex gap-2 mt-4">
                    <button
                      onClick={() => navigate(`/findings?scan_id=${uploadedScanId}`)}
                      className="btn-primary flex-1"
                    >
                      View Findings
                    </button>
                    <button
                      onClick={() => setUploadedScanId(null)}
                      className="btn-secondary"
                    >
                      Upload Another
                    </button>
                  </div>
                </div>
              )}

              {statusData.status === 'processing' && (
                <p className="text-gray-600">
                  Parsing vulnerability data and creating findings...
                </p>
              )}

              {statusData.status === 'failed' && statusData.error && (
                <div className="mt-2 p-3 bg-white rounded border border-red-200">
                  <p className="text-sm text-red-800">{statusData.error}</p>
                  <button
                    onClick={() => setUploadedScanId(null)}
                    className="mt-3 btn-secondary"
                  >
                    Try Again
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ScanUpload;