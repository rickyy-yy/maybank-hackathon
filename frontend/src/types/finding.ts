export interface Finding {
  id: string;
  source_scan_id: string;
  title: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  cvss_score?: number;
  cvss_vector?: string;
  cve_id?: string;
  cwe_id?: string;
  risk_score: number;
  priority_rank: number;
  affected_asset: string;
  asset_hostname?: string;
  port?: number;
  protocol?: string;
  service?: string;
  evidence?: string;
  remediation_guidance?: string;
  effort_hours?: number;
  status: 'open' | 'in_progress' | 'resolved' | 'false_positive';
  jira_ticket_key?: string;
  jira_ticket_url?: string;
  detected_date: string;
  resolved_date?: string;
}