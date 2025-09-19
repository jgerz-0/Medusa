export type ScanStatus = 'queued' | 'running' | 'completed' | 'failed';
export type FindingStatus = 'open' | 'acknowledged' | 'resolved';
export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface Target {
  id: string;
  name: string;
  scope: string;
  is_authorized: boolean;
  created_at: string;
  updated_at: string;
}

export interface Scan {
  id: string;
  target_id: string;
  target: string;
  scanner: string;
  status: ScanStatus;
  initiated_by?: string | null;
  created_at: string;
  updated_at: string;
  started_at?: string | null;
  completed_at?: string | null;
  findings_count: number;
}

export interface Finding {
  id: string;
  scan_id: string;
  title: string;
  description: string;
  cve_id?: string | null;
  severity: SeverityLevel;
  status: FindingStatus;
  template_id: string;
  detected_at: string;
  updated_at: string;
  evidence?: string | null;
  remediation?: string | null;
  enrichments: FindingEnrichment[];
}

export interface CVEAdvisory {
  source: string;
  identifier: string;
  summary?: string | null;
  severity?: string | null;
  cvss_score?: number | null;
  published?: string | null;
  modified?: string | null;
  references: string[];
  raw?: Record<string, unknown>;
}

export interface FindingEnrichment {
  id: string;
  job_id: string;
  generated_at: string;
  recorded_at: string;
  advisories: CVEAdvisory[];
  advisories_hash: string;
  errors: Record<string, string>;
  errors_hash: string;
  provenance: Record<string, unknown>;
  provenance_hash: string;
  payload_hash: string;
}
