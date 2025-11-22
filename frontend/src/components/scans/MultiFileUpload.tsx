import React, { useState } from 'react';
import { useDropzone } from 'react-dropzone';
import { Upload, FileText, X, AlertCircle, CheckCircle, Loader2, Trash2, ArrowRight } from 'lucide-react';
import { useNavigate } from 'react-router-dom';

interface FileWithPreview extends File {
  preview?: string;
  status?: 'pending' | 'uploading' | 'processing' | 'success' | 'error';
  scanId?: string;
  error?: string;
  uploadProgress?: number;
}

const MultiFileUpload: React.FC = () => {
  const [files, setFiles] = useState<FileWithPreview[]>([]);
  const [isUploading, setIsUploading] = useState(false);
  const navigate = useNavigate();

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    accept: {
      'text/xml': ['.xml', '.nessus'],
      'application/json': ['.json'],
      'text/csv': ['.csv'],
      'text/markdown': ['.md', '.markdown'],
    },
    disabled: isUploading,
    onDrop: (acceptedFiles) => {
      const newFiles: FileWithPreview[] = acceptedFiles.map(file => Object.assign(file, {
        preview: file.name,
        status: 'pending' as const
      }));
      setFiles(prev => [...prev, ...newFiles]);
    },
  });

  const removeFile = (fileName: string) => {
    setFiles(files.filter(f => f.name !== fileName));
  };

  const pollScanStatus = async (scanId: string, fileName: string, maxAttempts: number = 60): Promise<boolean> => {
    const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';
    
    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      try {
        const response = await fetch(`${API_URL}/api/v1/scans/${scanId}/status`);
        
        if (!response.ok) {
          throw new Error('Status check failed');
        }

        const status = await response.json();
        
        if (status.status === 'completed' || status.processed === true) {
          return true;
        } else if (status.status === 'failed') {
          throw new Error(status.error || 'Processing failed');
        }
        
        // Update progress indicator
        setFiles(prev => prev.map(f => 
          f.name === fileName 
            ? { ...f, uploadProgress: Math.min(50 + (attempt * 2), 95) }
            : f
        ));
        
        // Wait 2 seconds before next check
        await new Promise(resolve => setTimeout(resolve, 2000));
      } catch (error) {
        console.error('Status poll error:', error);
        // Continue polling unless it's the last attempt
        if (attempt === maxAttempts - 1) {
          throw error;
        }
      }
    }
    
    throw new Error('Processing timeout - please check the scans list');
  };

  const uploadFiles = async () => {
    if (files.length === 0) return;

    setIsUploading(true);
    const uploadedScanIds: string[] = [];

    // Upload files sequentially
    for (const file of files) {
      try {
        // Update status to uploading
        setFiles(prev => prev.map(f => 
          f.name === file.name ? { ...f, status: 'uploading' as const, uploadProgress: 10 } : f
        ));

        const formData = new FormData();
        formData.append('file', file);

        const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';
        
        // Upload with auto-detect
        const uploadResponse = await fetch(
          `${API_URL}/api/v1/scans/upload?source_tool=auto`,
          {
            method: 'POST',
            body: formData,
          }
        );

        if (!uploadResponse.ok) {
          const errorData = await uploadResponse.json();
          throw new Error(errorData.detail || 'Upload failed');
        }

        const uploadData = await uploadResponse.json();
        const scanId = uploadData.scan_id;
        
        // Update status to processing
        setFiles(prev => prev.map(f => 
          f.name === file.name 
            ? { ...f, status: 'processing' as const, scanId, uploadProgress: 30 } 
            : f
        ));

        // Poll for processing completion
        await pollScanStatus(scanId, file.name);
        
        // Update status to success
        setFiles(prev => prev.map(f => 
          f.name === file.name 
            ? { ...f, status: 'success' as const, uploadProgress: 100 } 
            : f
        ));
        
        uploadedScanIds.push(scanId);

      } catch (error) {
        console.error(`Error uploading ${file.name}:`, error);
        
        // Update status to error
        setFiles(prev => prev.map(f => 
          f.name === file.name 
            ? { 
                ...f, 
                status: 'error' as const, 
                error: error instanceof Error ? error.message : 'Upload failed',
                uploadProgress: 0
              } 
            : f
        ));
      }
    }

    setIsUploading(false);

    // If all successful, show option to view findings
    if (uploadedScanIds.length === files.length) {
      console.log('All files uploaded successfully:', uploadedScanIds);
    }
  };

  const getStatusIcon = (status?: string) => {
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

  const getStatusColor = (status?: string) => {
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

  const getStatusText = (file: FileWithPreview) => {
    switch (file.status) {
      case 'uploading':
        return 'Uploading...';
      case 'processing':
        return `Processing... ${file.uploadProgress || 0}%`;
      case 'success':
        return 'Completed';
      case 'error':
        return file.error || 'Failed';
      default:
        return 'Pending';
    }
  };

  const allFilesSuccessful = files.length > 0 && files.every(f => f.status === 'success');
  const hasErrors = files.some(f => f.status === 'error');
  const successCount = files.filter(f => f.status === 'success').length;

  return (
    <div className="space-y-6">
      {/* Upload Area */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-xl font-semibold">Upload Scan Files</h2>
            <p className="text-sm text-gray-600 mt-1">
              Drag and drop multiple files • Auto-detection enabled
            </p>
          </div>
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
                Supports: XML, JSON, CSV, Markdown • Unlimited files • Auto-detection
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
            {!isUploading && files.length > 0 && (
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
            {files.map((file, index) => (
              <div
                key={index}
                className={`flex items-center gap-3 p-3 rounded-lg border ${getStatusColor(file.status)}`}
              >
                {getStatusIcon(file.status)}
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-gray-900 truncate">
                    {file.name}
                  </p>
                  <div className="flex items-center gap-2 text-xs text-gray-500">
                    <span>{(file.size / 1024).toFixed(2)} KB</span>
                    <span>•</span>
                    <span>{getStatusText(file)}</span>
                  </div>
                  {file.status === 'processing' && file.uploadProgress && (
                    <div className="mt-2 w-full bg-gray-200 rounded-full h-1.5">
                      <div 
                        className="bg-purple-600 h-1.5 rounded-full transition-all duration-300" 
                        style={{ width: `${file.uploadProgress}%` }}
                      />
                    </div>
                  )}
                </div>
                {file.status === 'pending' && !isUploading && (
                  <button
                    onClick={() => removeFile(file.name)}
                    className="text-gray-400 hover:text-red-600"
                  >
                    <X className="w-5 h-5" />
                  </button>
                )}
              </div>
            ))}
          </div>

          {/* Upload Button */}
          {!allFilesSuccessful && (
            <button
              onClick={uploadFiles}
              disabled={isUploading || files.every(f => f.status !== 'pending')}
              className="w-full px-4 py-3 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors disabled:bg-gray-400 disabled:cursor-not-allowed flex items-center justify-center gap-2 font-medium"
            >
              {isUploading ? (
                <>
                  <Loader2 className="w-5 h-5 animate-spin" />
                  Processing {files.filter(f => f.status === 'uploading' || f.status === 'processing').length} / {files.length}
                </>
              ) : (
                `Upload ${files.filter(f => f.status === 'pending').length} File${files.filter(f => f.status === 'pending').length !== 1 ? 's' : ''}`
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
                  onClick={() => navigate('/findings')}
                  className="flex-1 px-4 py-3 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors flex items-center justify-center gap-2 font-medium"
                >
                  View All Findings
                  <ArrowRight className="w-4 h-4" />
                </button>
                <button
                  onClick={() => setFiles([])}
                  className="px-4 py-3 bg-white text-gray-700 rounded-md hover:bg-gray-50 transition-colors border border-gray-300"
                >
                  Upload More
                </button>
              </div>
            </div>
          )}

          {/* Partial Success/Error */}
          {hasErrors && !isUploading && (
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
                <li>📁 <strong>Unlimited Files:</strong> Upload as many files as you need</li>
                <li>🎯 <strong>Supported Formats:</strong> Nessus, Nmap, CSV, Markdown, JSON</li>
                <li>⚡ <strong>Real-Time Processing:</strong> Track progress for each file</li>
                <li>🔄 <strong>Error Recovery:</strong> Failed files don't block others</li>
              </ul>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default MultiFileUpload;