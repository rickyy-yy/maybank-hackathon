export interface Scan {
  id string;
  filename string;
  source_tool string;
  upload_date string;
  total_findings number;
  critical_count number;
  high_count number;
  medium_count number;
  low_count number;
  info_count number;
  processed boolean;
  processing_error string;
}