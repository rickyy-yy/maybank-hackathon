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
    queryFn: