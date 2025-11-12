import api from './api';
import { Scan } from '../types/scan';

export const scanService = {
  async uploadScan(file: File, sourceTool: string = 'nessus'): Promise<any> {
    const formData = new FormData();
    formData.append('file', file);
    
    const response = await api.post(
      `/api/v1/scans/upload?source_tool=${sourceTool}`,
      formData,
      {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      }
    );
    
    return response.data;
  },

  async getScans(limit: number = 50, offset: number = 0): Promise<{ scans: Scan[]; total: number }> {
    const response = await api.get(`/api/v1/scans?limit=${limit}&offset=${offset}`);
    return response.data;
  },

  async getScan(scanId: string): Promise<Scan> {
    const response = await api.get(`/api/v1/scans/${scanId}`);
    return response.data;
  },

  async getScanStatus(scanId: string): Promise<any> {
    const response = await api.get(`/api/v1/scans/${scanId}/status`);
    return response.data;
  },
};