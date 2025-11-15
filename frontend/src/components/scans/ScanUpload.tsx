import React, { useState, useEffect } from 'react';
import { useDropzone } from 'react-dropzone';
import { Upload, FileText, AlertCircle, CheckCircle, Loader2, ArrowRight } from 'lucide-react';
import { useUploadScan, useScanStatus } from '../../hooks/useScans';
import { useNavigate } from 'react-router-dom';

const ScanUpload: React.FC = () => {
  const [uploadedScanId, setUploadedScanId] = useState<string | null>(null);
  const [sourceTool, setSourceTool] = useState('nessus');
  const [autoNavigate, setAutoNavigate] = useState(true);
  const navigate = useNavigate();
  
  const uploadMutation = useUploadScan();
  const { data: statusData, isError: statusError, refetch: refetchStatus } = useScanStatus(
    uploadedScanId || '', 
    !!uploadedScanId
  );

  // Handle auto-navigation when processing completes
  useEffect(() => {
    if (statusData?.status === 'completed' && autoNavigate && uploadedScanId) {
      // Wait 2 seconds to show success message, then navigate
      const timer = setTimeout(() => {
        navigate(`/findings?scan_id=${uploadedScanId}`);
      }, 2000);
      
      return () => clearTimeout(timer);
    }
  }, [statusData?.status, autoNavigate, uploadedScanId, navigate]);

  // Force refetch status every 2 seconds while processing
  useEffect(() => {
    if (uploadedScanId && statusData?.status === 'processing') {
      const interval = setInterval(() => {
        refetchStatus();
      }, 2000);
      
      return () => clearInterval(interval);
    }
  }, [uploadedScanId, statusData?.status, refetchStatus]);

  // Reset upload state
  const handleReset = () => {
    setUploadedScanId(null);
    setAutoNavigate(true);
  };

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
          setAutoNavigate(true);
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
        return <Loader2 className="w-6 h-6 text-blue-600 animate-spin" />;
      case 'completed':
        return <CheckCircle className="w-6 h-6 text-green-600" />;
      case 'failed':
        return <AlertCircle className="w-6 h-6 text-red-600" />;
      default:
        return null;
    }
  };

  const getStatusColor = () => {
    if (!statusData) return '';
    
    switch (statusData.status) {
      case 'processing':
        return 'border-blue-300 bg-blue-50';
      case 'completed':
        return 'border-green-300 bg-green-50';
      case 'failed':
        return 'border-red-300 bg-red-50';
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
            <>
              <Loader2 className="w-8 h-8 text-blue-600 animate-spin mx-auto mb-2" />
              <p className="text-lg text-gray-600">Uploading file...</p>
            </>
          ) : statusData?.status === 'processing' ? (
            <>
              <Loader2 className="w-8 h-8 text-blue-600 animate-spin mx-auto mb-2" />
              <p className="text-lg text-gray-600">Processing scan data...</p>
            </>
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
          <div className="mt-4 p-4 bg-red-50 border border-red-200 rounded-lg flex items-start gap-3">
            <AlertCircle className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" />
            <div>
              <p className="font-semibold text-red-800">Upload Failed</p>
              <p className="text-sm text-red-700 mt-1">
                {(uploadMutation.error as Error).message}
              </p>
            </div>
          </div>
        )}

        {/* Status Error */}
        {statusError && uploadedScanId && (
          <div className="mt-4 p-4 bg-yellow-50 border border-yellow-200 rounded-lg flex items-start gap-3">
            <AlertCircle className="w-5 h-5 text-yellow-600 flex-shrink-0 mt-0.5" />
            <div>
              <p className="font-semibold text-yellow-800">Status Check Failed</p>
              <p className="text-sm text-yellow-700 mt-1">
                Unable to fetch scan status. The scan may still be processing.
                Check the "All Scans" tab for results.
              </p>
            </div>
          </div>
        )}
      </div>

      {/* Processing Status */}
      {statusData && (
        <div className={`card border-2 ${getStatusColor()}`}>
          <div className="flex items-start gap-4">
            <div className="mt-1">{getStatusIcon()}</div>
            <div className="flex-1">
              <h3 className="text-lg font-semibold mb-2 flex items-center gap-2">
                {statusData.status === 'processing' && (
                  <>
                    <span>Processing Scan</span>
                    <span className="text-sm font-normal text-gray-600">(This may take a minute)</span>
                  </>
                )}
                {statusData.status === 'completed' && '✅ Scan Processing Complete'}
                {statusData.status === 'failed' && '❌ Processing Failed'}
              </h3>

              {/* Processing Status */}
              {statusData.status === 'processing' && (
                <div className="space-y-3">
                  <div className="flex items-center gap-2 text-sm text-gray-700">
                    <div className="w-2 h-2 bg-blue-600 rounded-full animate-pulse"></div>
                    <span>Parsing vulnerability data and creating findings...</span>
                  </div>
                  <div className="bg-white rounded p-3 border border-blue-200">
                    <p className="text-xs text-blue-800">
                      <strong>Processing Steps:</strong>
                    </p>
                    <ol className="text-xs text-blue-700 mt-1 space-y-1 list-decimal list-inside">
                      <li>Parsing scan file format</li>
                      <li>Extracting vulnerability data</li>
                      <li>Calculating risk scores</li>
                      <li>Applying remediation guidance with web search</li>
                      <li>Prioritizing findings</li>
                    </ol>
                  </div>
                </div>
              )}

              {/* Completed Status */}
              {statusData.status === 'completed' && statusData.statistics && (
                <div className="space-y-4">
                  <div className="flex items-center gap-2 text-green-700">
                    <CheckCircle className="w-5 h-5" />
                    <p className="font-medium">
                      Successfully processed{' '}
                      <span className="font-bold">{statusData.total_findings}</span> findings
                    </p>
                  </div>
                  
                  {/* Severity Breakdown */}
                  <div className="grid grid-cols-5 gap-3">
                    <div className="text-center bg-white rounded p-3 border border-red-200">
                      <div className="text-2xl font-bold text-red-600">
                        {statusData.statistics.critical}
                      </div>
                      <div className="text-xs text-gray-600 mt-1">Critical</div>
                    </div>
                    <div className="text-center bg-white rounded p-3 border border-orange-200">
                      <div className="text-2xl font-bold text-orange-600">
                        {statusData.statistics.high}
                      </div>
                      <div className="text-xs text-gray-600 mt-1">High</div>
                    </div>
                    <div className="text-center bg-white rounded p-3 border border-yellow-200">
                      <div className="text-2xl font-bold text-yellow-600">
                        {statusData.statistics.medium}
                      </div>
                      <div className="text-xs text-gray-600 mt-1">Medium</div>
                    </div>
                    <div className="text-center bg-white rounded p-3 border border-green-200">
                      <div className="text-2xl font-bold text-green-600">
                        {statusData.statistics.low}
                      </div>
                      <div className="text-xs text-gray-600 mt-1">Low</div>
                    </div>
                    <div className="text-center bg-white rounded p-3 border border-blue-200">
                      <div className="text-2xl font-bold text-blue-600">
                        {statusData.statistics.info}
                      </div>
                      <div className="text-xs text-gray-600 mt-1">Info</div>
                    </div>
                  </div>

                  {/* Navigation Options */}
                  <div className="flex gap-3 pt-2">
                    <button
                      onClick={() => navigate(`/findings?scan_id=${uploadedScanId}`)}
                      className="flex-1 px-4 py-3 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors flex items-center justify-center gap-2 font-medium"
                    >
                      View Findings
                      <ArrowRight className="w-4 h-4" />
                    </button>
                    <button
                      onClick={handleReset}
                      className="px-4 py-3 bg-white text-gray-700 rounded-md hover:bg-gray-50 transition-colors border border-gray-300"
                    >
                      Upload Another
                    </button>
                  </div>

                  {autoNavigate && (
                    <p className="text-xs text-center text-gray-600 flex items-center justify-center gap-2">
                      <Loader2 className="w-3 h-3 animate-spin" />
                      Redirecting to findings in 2 seconds...
                    </p>
                  )}
                </div>
              )}

              {/* Failed Status */}
              {statusData.status === 'failed' && (
                <div className="space-y-3">
                  {statusData.error && (
                    <div className="bg-white rounded p-3 border border-red-200">
                      <p className="text-sm font-semibold text-red-800 mb-1">Error Details:</p>
                      <p className="text-sm text-red-700">{statusData.error}</p>
                    </div>
                  )}
                  
                  <div className="bg-white rounded p-3 border border-red-200">
                    <p className="text-sm font-semibold text-red-800 mb-2">Troubleshooting:</p>
                    <ul className="text-sm text-red-700 space-y-1 list-disc list-inside">
                      <li>Verify the scan file is not corrupted</li>
                      <li>Ensure the file format matches the selected scanner tool</li>
                      <li>Check that the file contains valid vulnerability data</li>
                      <li>Try exporting the scan again from your scanner</li>
                    </ul>
                  </div>
                  
                  <button
                    onClick={handleReset}
                    className="w-full px-4 py-2 bg-red-600 text-white rounded-md hover:bg-red-700 transition-colors"
                  >
                    Try Again
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Info Card */}
      {!uploadedScanId && (
        <div className="card bg-blue-50 border border-blue-200">
          <div className="flex items-start gap-3">
            <FileText className="w-5 h-5 text-blue-600 flex-shrink-0 mt-0.5" />
            <div>
              <h3 className="font-semibold text-blue-900 mb-2">Enhanced Remediation Guidance</h3>
              <p className="text-sm text-blue-800 mb-2">
                Our system now includes web search capabilities to provide:
              </p>
              <ul className="text-sm text-blue-700 space-y-1 list-disc list-inside">
                <li>Latest security advisories and patches</li>
                <li>Real-time CVE information from NVD</li>
                <li>Vendor-specific remediation guides</li>
                <li>OWASP best practices and cheat sheets</li>
                <li>Current exploit availability status</li>
              </ul>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ScanUpload;