import React, { useState } from 'react';
import { Upload, List } from 'lucide-react';
import ScanUpload from '../components/scans/ScanUpload';
import ScanList from '../components/scans/ScanList';

const ScansPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'upload' | 'list'>('upload');

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-3xl font-bold text-gray-900 mb-2">Vulnerability Scans</h1>
        <p className="text-gray-600">
          Upload and manage vulnerability scan reports from Nessus, Burp Suite, and Nmap
        </p>
      </div>

      {/* Tabs */}
      <div className="mb-6 border-b border-gray-200">
        <nav className="flex gap-4">
          <button
            onClick={() => setActiveTab('upload')}
            className={`pb-3 px-1 border-b-2 font-medium text-sm transition-colors ${
              activeTab === 'upload'
                ? 'border-blue-600 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
            }`}
          >
            <div className="flex items-center gap-2">
              <Upload className="w-4 h-4" />
              Upload Scan
            </div>
          </button>
          <button
            onClick={() => setActiveTab('list')}
            className={`pb-3 px-1 border-b-2 font-medium text-sm transition-colors ${
              activeTab === 'list'
                ? 'border-blue-600 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
            }`}
          >
            <div className="flex items-center gap-2">
              <List className="w-4 h-4" />
              All Scans
            </div>
          </button>
        </nav>
      </div>

      {/* Tab Content */}
      {activeTab === 'upload' ? <ScanUpload /> : <ScanList />}
    </div>
  );
};

export default ScansPage;