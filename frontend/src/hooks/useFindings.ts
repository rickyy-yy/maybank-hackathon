import { useQuery } from '@tanstack/react-query';
import { findingService } from '../services/findingService';

export const useFindings = (params?: {
  scanId?: string;
  severity?: string;
  status?: string;
  limit?: number;
  offset?: number;
}) => {
  return useQuery({
    queryKey: ['findings', params],
    queryFn: () => findingService.getFindings(params),
  });
};

export const useFinding = (findingId: string) => {
  return useQuery({
    queryKey: ['finding', findingId],
    queryFn: () => findingService.getFinding(findingId),
    enabled: !!findingId,
  });
};