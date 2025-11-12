import api from './api';
import { Finding } from '../types/finding';

export const findingService = {
  async getFindings(params?: {
    scanId?: string;
    severity?: string;
    status?: string;
    limit?: number;
    offset?: number;
  }): Promise<{ findings: Finding[]; total: number }> {
    const response = await api.get('/api/v1/findings', { params });
    return response.data;
  },

  async getFinding(findingId: string): Promise<Finding> {
    const response = await api.get(`/api/v1/findings/${findingId}`);
    return response.data;
  },
};