import { useState } from 'react';
import { Upload, List, Files } from 'lucide-react';
import ScanUpload from '../components/scans/ScanUpload';
import MultiFileUpload from '../components/scans/MultiFileUpload';
import ScanList from '../components/scans/ScanList';

const ScansPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'single' | 'multi' | 'list'>('multi');

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-3xl font-bold text-gray-900 mb-2">Vulnerability Scans</h1>
        <p className="text-gray-600">
          Upload and manage vulnerability scan reports
        </p>
      </div>

      {/* Tabs */}
      <div className="mb-6 border-b border-gray-200">
        <nav className="flex gap-4">
          <button
            onClick={() => setActiveTab('multi')}
            className={`pb-3 px-1 border-b-2 font-medium text-sm transition-colors ${
              activeTab === 'multi'
                ? 'border-blue-600 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700'
            }`}
          >
            <div className="flex items-center gap-2">
              <Files className="w-4 h-4" />
              Multi-File Upload
            </div>
          </button>
          <button
            onClick={() => setActiveTab('single')}
            className={`pb-3 px-1 border-b-2 font-medium text-sm transition-colors ${
              activeTab === 'single'
                ? 'border-blue-600 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700'
            }`}
          >
            <div className="flex items-center gap-2">
              <Upload className="w-4 h-4" />
              Single File Upload
            </div>
          </button>
          <button
            onClick={() => setActiveTab('list')}
            className={`pb-3 px-1 border-b-2 font-medium text-sm transition-colors ${
              activeTab === 'list'
                ? 'border-blue-600 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700'
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
      {activeTab === 'multi' && <MultiFileUpload />}
      {activeTab === 'single' && <ScanUpload />}
      {activeTab === 'list' && <ScanList />}
    </div>
  );
};

export default ScansPage;