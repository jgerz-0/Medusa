export type ScanStatus = 'queued' | 'running' | 'completed' | 'failed';
export type FindingStatus = 'open' | 'acknowledged' | 'resolved';
export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface Target {
  id: string;
  name: string;
  url: string;
  scope: Record<string, unknown>;
  is_authorized: boolean;
  created_at: string;
  updated_at: string;
}

export interface Scan {
  id: string;
  target: string;
  profile?: string;
  status: ScanStatus;
  created_at: string;
  updated_at: string;
  findings_count: number;
}

export interface Finding {
  id: string;
  scan_id: string;
  title: string;
  severity: SeverityLevel;
  status: FindingStatus;
  template_id: string;
  detected_at: string;
  updated_at: string;
  evidence?: string;
  remediation?: string;
}
