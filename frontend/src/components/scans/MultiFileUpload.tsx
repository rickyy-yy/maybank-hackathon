import React, { useState, useCallback } from 'react';
import { useDropzone } from 'react-dropzone';
import { Upload, FileText, X, AlertCircle, CheckCircle, Loader2, Trash2, ArrowRight } from 'lucide-react';
import { useNavigate } from 'react-router-dom';

interface UploadFile {
  id: string;
  file: File;
  status: 'pending' | 'uploading' | 'processing' | 'success' | 'error';
  scanId?: string;
  error?: string;
  progress: number;
}

const MultiFileUpload: React.FC = () => {
  const [files, setFiles] = useState<UploadFile[]>([]);
  const [isUploading, setIsUploading] = useState(false);
  const [batchId, setBatchId] = useState<string | null>(null);
  const [batchName, setBatchName] = useState<string>('');
  const navigate = useNavigate();

  const updateFileState = useCallback((id: string, updates: Partial<UploadFile>) => {
    setFiles(prev => prev.map(f => f.id === id ? { ...f, ...updates } : f));
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    accept: {
      'text/xml': ['.xml', '.nessus'],
      'application/json': ['.json'],
      'text/csv': ['.csv'],
      'text/markdown': ['.md', '.markdown'],
    },
    disabled: isUploading,
    multiple: true, // Always allow multiple files
    onDrop: (acceptedFiles) => {
      const newFiles: UploadFile[] = acceptedFiles.map(file => ({
        id: `${file.name}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
        file,
        status: 'pending',
        progress: 0
      }));
      setFiles(prev => [...prev, ...newFiles]);
    },
  });

  const removeFile = (id: string) => {
    setFiles(prev => prev.filter(f => f.id !== id));
  };

  const pollScanStatus = async (
    scanId: string, 
    fileId: string, 
    maxAttempts: number = 60
  ): Promise<boolean> => {
    const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';
    
    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      try {
        const response = await fetch(`${API_URL}/api/v1/scans/${scanId}/status`);
        
        if (!response.ok) {
          throw new Error('Status check failed');
        }

        const status = await response.json();
        
        // Update progress smoothly - from 30% to 95% over polling attempts
        const baseProgress = 30;
        const progressRange = 65; // 95 - 30
        const currentProgress = baseProgress + Math.floor((attempt / maxAttempts) * progressRange);
        updateFileState(fileId, { progress: Math.min(currentProgress, 95) });
        
        if (status.status === 'completed' || status.processed === true) {
          // Set to 100% on completion
          updateFileState(fileId, { progress: 100 });
          return true;
        } else if (status.status === 'failed') {
          throw new Error(status.error || 'Processing failed');
        }
        
        // Wait 2 seconds before next check
        await new Promise(resolve => setTimeout(resolve, 2000));
      } catch (error) {
        console.error('Status poll error:', error);
        if (attempt === maxAttempts - 1) {
          throw error;
        }
      }
    }
    
    throw new Error('Processing timeout - please check the scans list');
  };

  const uploadFiles = async () => {
    const pendingFiles = files.filter(f => f.status === 'pending');
    if (pendingFiles.length === 0) return;

    setIsUploading(true);
    
    const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';
    
    // Create a batch for this upload session
    let currentBatchId = batchId;
    if (!currentBatchId) {
      try {
        const batchResponse = await fetch(`${API_URL}/api/v1/scans/batches`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ 
            name: batchName || `Upload ${new Date().toLocaleString()}` 
          }),
        });
        
        if (batchResponse.ok) {
          const batchData = await batchResponse.json();
          currentBatchId = batchData.batch_id;
          setBatchId(currentBatchId);
        }
      } catch (error) {
        console.error('Failed to create batch:', error);
      }
    }

    for (const uploadFile of pendingFiles) {
      try {
        // Start uploading - show progress
        updateFileState(uploadFile.id, { status: 'uploading', progress: 10 });

        const formData = new FormData();
        formData.append('file', uploadFile.file);
        
        // Simulate upload progress (10% to 25%)
        updateFileState(uploadFile.id, { progress: 15 });
        
        // Include batch_id in the upload URL
        let uploadUrl = `${API_URL}/api/v1/scans/upload?source_tool=auto`;
        if (currentBatchId) {
          uploadUrl += `&batch_id=${currentBatchId}`;
        }
        
        updateFileState(uploadFile.id, { progress: 20 });
        
        const uploadResponse = await fetch(uploadUrl, {
          method: 'POST',
          body: formData,
        });

        updateFileState(uploadFile.id, { progress: 25 });

        if (!uploadResponse.ok) {
          const errorData = await uploadResponse.json();
          throw new Error(errorData.detail || 'Upload failed');
        }

        const uploadData = await uploadResponse.json();
        const scanId = uploadData.scan_id;
        
        // Upload complete, now processing starts
        updateFileState(uploadFile.id, { 
          status: 'processing', 
          scanId, 
          progress: 30 
        });

        // Poll for processing status with progress updates
        await pollScanStatus(scanId, uploadFile.id);
        
        // Mark as success
        updateFileState(uploadFile.id, { status: 'success', progress: 100 });

      } catch (error) {
        console.error(`Error uploading ${uploadFile.file.name}:`, error);
        updateFileState(uploadFile.id, { 
          status: 'error', 
          error: error instanceof Error ? error.message : 'Upload failed',
          progress: 0
        });
      }
    }

    setIsUploading(false);
  };

  const getStatusIcon = (status: UploadFile['status']) => {
    switch (status) {
      case 'uploading':
        return <Loader2 className="w-5 h-5 text-blue-600 animate-spin" />;
      case 'processing':
        return <Loader2 className="w-5 h-5 text-purple-600 animate-spin" />;
      case 'success':
        return <CheckCircle className="w-5 h-5 text-green-600" />;
      case 'error':
        return <AlertCircle className="w-5 h-5 text-red-600" />;
      default:
        return <FileText className="w-5 h-5 text-gray-400" />;
    }
  };

  const getStatusColor = (status: UploadFile['status']) => {
    switch (status) {
      case 'uploading':
        return 'border-blue-300 bg-blue-50';
      case 'processing':
        return 'border-purple-300 bg-purple-50';
      case 'success':
        return 'border-green-300 bg-green-50';
      case 'error':
        return 'border-red-300 bg-red-50';
      default:
        return 'border-gray-200 bg-white';
    }
  };

  const getProgressBarColor = (status: UploadFile['status']) => {
    switch (status) {
      case 'uploading':
        return 'bg-blue-600';
      case 'processing':
        return 'bg-purple-600';
      case 'success':
        return 'bg-green-600';
      default:
        return 'bg-gray-400';
    }
  };

  const getStatusText = (file: UploadFile) => {
    switch (file.status) {
      case 'uploading':
        return `Uploading... ${file.progress}%`;
      case 'processing':
        return `Processing... ${file.progress}%`;
      case 'success':
        return 'Completed';
      case 'error':
        return file.error || 'Failed';
      default:
        return 'Pending';
    }
  };

  const pendingCount = files.filter(f => f.status === 'pending').length;
  const allFilesSuccessful = files.length > 0 && files.every(f => f.status === 'success');
  const hasErrors = files.some(f => f.status === 'error');
  const successCount = files.filter(f => f.status === 'success').length;
  const activeCount = files.filter(f => f.status === 'uploading' || f.status === 'processing').length;

  return (
    <div className="space-y-6">
      {/* Upload Area */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-xl font-semibold">Upload Scan Files</h2>
            <p className="text-sm text-gray-600 mt-1">
              Drag and drop multiple files • Auto-detection enabled • Duplicate detection
            </p>
          </div>
        </div>

        {/* Batch Name Input */}
        <div className="mb-4">
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Batch Name (Optional)
          </label>
          <input
            type="text"
            value={batchName}
            onChange={(e) => setBatchName(e.target.value)}
            placeholder="e.g., Weekly Scan - Nov 2025"
            className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
            disabled={isUploading}
          />
          <p className="text-xs text-gray-500 mt-1">
            Group these uploads together for easier tracking and duplicate detection
          </p>
        </div>

        {/* Dropzone */}
        <div
          {...getRootProps()}
          className={`border-2 border-dashed rounded-lg p-12 text-center cursor-pointer transition-colors ${
            isDragActive
              ? 'border-blue-500 bg-blue-50'
              : isUploading
              ? 'border-gray-200 bg-gray-50 cursor-not-allowed'
              : 'border-gray-300 hover:border-gray-400'
          }`}
        >
          <input {...getInputProps()} />
          <Upload className="w-12 h-12 text-gray-400 mx-auto mb-4" />
          {isDragActive ? (
            <p className="text-lg text-blue-600">Drop the files here...</p>
          ) : (
            <>
              <p className="text-lg text-gray-700 mb-2">
                Drag and drop scan files here, or click to select
              </p>
              <p className="text-sm text-gray-500">
                Supports: XML, JSON, CSV, Markdown • Multiple files • Auto-detection
              </p>
            </>
          )}
        </div>
      </div>

      {/* File List */}
      {files.length > 0 && (
        <div className="card">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold">
              Files ({files.length})
            </h3>
            {!isUploading && (
              <button
                onClick={() => setFiles([])}
                className="text-sm text-red-600 hover:text-red-800 flex items-center gap-1"
              >
                <Trash2 className="w-4 h-4" />
                Clear All
              </button>
            )}
          </div>

          <div className="space-y-2 mb-4">
            {files.map((uploadFile) => (
              <div
                key={uploadFile.id}
                className={`flex items-center gap-3 p-3 rounded-lg border ${getStatusColor(uploadFile.status)}`}
              >
                {getStatusIcon(uploadFile.status)}
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-gray-900 truncate">
                    {uploadFile.file.name}
                  </p>
                  <div className="flex items-center gap-2 text-xs text-gray-500">
                    <span>{(uploadFile.file.size / 1024).toFixed(2)} KB</span>
                    <span>•</span>
                    <span>{getStatusText(uploadFile)}</span>
                  </div>
                  {/* Progress bar - show for uploading and processing */}
                  {(uploadFile.status === 'uploading' || uploadFile.status === 'processing') && (
                    <div className="mt-2 w-full bg-gray-200 rounded-full h-2">
                      <div 
                        className={`h-2 rounded-full transition-all duration-500 ease-out ${getProgressBarColor(uploadFile.status)}`}
                        style={{ width: `${uploadFile.progress}%` }}
                      />
                    </div>
                  )}
                </div>
                {uploadFile.status === 'pending' && !isUploading && (
                  <button
                    onClick={() => removeFile(uploadFile.id)}
                    className="text-gray-400 hover:text-red-600"
                  >
                    <X className="w-5 h-5" />
                  </button>
                )}
              </div>
            ))}
          </div>

          {/* Upload Button */}
          {!allFilesSuccessful && pendingCount > 0 && (
            <button
              onClick={uploadFiles}
              disabled={isUploading}
              className="w-full px-4 py-3 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors disabled:bg-gray-400 disabled:cursor-not-allowed flex items-center justify-center gap-2 font-medium"
            >
              {isUploading ? (
                <>
                  <Loader2 className="w-5 h-5 animate-spin" />
                  Processing {activeCount} of {pendingCount}
                </>
              ) : (
                `Upload ${pendingCount} File${pendingCount !== 1 ? 's' : ''}`
              )}
            </button>
          )}

          {/* Success Actions */}
          {allFilesSuccessful && (
            <div className="space-y-3">
              <div className="bg-green-50 border border-green-200 rounded-lg p-4">
                <div className="flex items-center gap-2">
                  <CheckCircle className="w-5 h-5 text-green-600" />
                  <p className="text-sm font-semibold text-green-800">
                    Successfully uploaded all {files.length} files!
                  </p>
                </div>
              </div>
              <div className="flex gap-3">
                <button
                  onClick={() => navigate(batchId ? `/findings?batch_id=${batchId}` : '/findings')}
                  className="flex-1 px-4 py-3 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors flex items-center justify-center gap-2 font-medium"
                >
                  View All Findings
                  <ArrowRight className="w-4 h-4" />
                </button>
                <button
                  onClick={() => {
                    setFiles([]);
                    setBatchId(null);
                    setBatchName('');
                  }}
                  className="px-4 py-3 bg-white text-gray-700 rounded-md hover:bg-gray-50 transition-colors border border-gray-300"
                >
                  Upload More
                </button>
              </div>
            </div>
          )}

          {/* Partial Success/Error */}
          {hasErrors && !isUploading && successCount > 0 && (
            <div className="mt-4 bg-orange-50 border border-orange-200 rounded-lg p-4">
              <div className="flex items-center gap-2">
                <AlertCircle className="w-5 h-5 text-orange-600" />
                <div>
                  <p className="text-sm font-semibold text-orange-800">
                    Uploaded {successCount} of {files.length} files
                  </p>
                  <p className="text-xs text-orange-700 mt-1">
                    Some files failed to upload. Check error messages above.
                  </p>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Info Card */}
      {files.length === 0 && (
        <div className="card bg-blue-50 border border-blue-200">
          <div className="flex items-start gap-3">
            <FileText className="w-5 h-5 text-blue-600 flex-shrink-0 mt-0.5" />
            <div>
              <h3 className="font-semibold text-blue-900 mb-2">Multi-File Upload</h3>
              <ul className="text-sm text-blue-800 space-y-1">
                <li>✨ <strong>Auto-Detection:</strong> Automatically identifies file format</li>
                <li>📁 <strong>Multiple Files:</strong> Upload as many files as you need at once</li>
                <li>🎯 <strong>Supported Formats:</strong> Nessus, Nmap, CSV, Markdown, JSON</li>
                <li>⚡ <strong>Real-Time Progress:</strong> Track upload and processing for each file</li>
                <li>🔄 <strong>Error Recovery:</strong> Failed files don't block others</li>
                <li>🔍 <strong>Duplicate Detection:</strong> Automatic within batches</li>
              </ul>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default MultiFileUpload;