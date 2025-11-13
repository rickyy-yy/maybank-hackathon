import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { scanService } from '../services/scanService';

export const useScans = () => {
  return useQuery({
    queryKey: ['scans'],
    queryFn: () => scanService.getScans(),
  });
};

export const useScan = (scanId: string) => {
  return useQuery({
    queryKey: ['scan', scanId],
    queryFn: () => scanService.getScan(scanId),
    enabled: !!scanId,
  });
};

export const useScanStatus = (scanId: string, enabled: boolean = true) => {
  return useQuery({
    queryKey: ['scanStatus', scanId],
    queryFn: () => scanService.getScanStatus(scanId),
    enabled: !!scanId && enabled,
    refetchInterval: (data) => {
      // Poll every 2 seconds if still processing
      if (data && data.status === 'processing') {
        return 2000;
      }
      return false;
    },
  });
};

export const useUploadScan = () => {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ file, sourceTool }: { file: File; sourceTool: string }) =>
      scanService.uploadScan(file, sourceTool),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] });
    },
  });
};