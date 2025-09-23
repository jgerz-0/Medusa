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

export type DiscoveryDiffStatus = 'approved' | 'in_scope' | 'scope_extension' | 'unmatched';

export interface ReconDiscovery {
  id: string;
  source: string;
  asset_type: string;
  value: string;
  raw_value?: string | null;
  matched_scope?: string | null;
  metadata: Record<string, unknown>;
  status: string;
  diff_status: DiscoveryDiffStatus;
  first_seen: string;
  last_seen: string;
  occurrences: number;
  approved_target_id?: string | null;
}

export interface ReconRun {
  id: string;
  job_id: string;
  source: string;
  mode: string;
  status: string;
  retrieved_at: string;
  authorized_scopes: string[];
  tooling: Record<string, unknown>;
  targets: Record<string, unknown>[];
  observation_count: number;
  created_at: string;
  updated_at: string;
}

export interface ReconObservation {
  id: string;
  run_id: string;
  target_id?: string | null;
  asset_type: string;
  normalized_value: string;
  raw_value?: string | null;
  matched_scope?: string | null;
  port?: number | null;
  occurrences: number;
  metadata: Record<string, unknown>;
  first_seen: string;
  last_seen: string;
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
  scanner: string;
  sample_id: string | null;
  tool: string | null;
  category: string | null;
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
  metadata: Record<string, unknown>;
  assigned_to?: string | null;
  tags: string[];
  comment_count: number;
  tickets: FindingTicket[];
  scope_status: 'unknown' | 'in_scope' | 'out_of_scope' | 'mixed';
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

export interface FindingComment {
  id: string;
  author: string;
  message: string;
  created_at: string;
}

export interface FindingTimelineEvent {
  kind: string;
  actor: string;
  created_at: string;
  message?: string | null;
  metadata: Record<string, unknown>;
}

export interface FindingsTimelineBucket {
  date: string;
  open: number;
  acknowledged: number;
  resolved: number;
  total: number;
}

export interface FindingTicket {
  id: string;
  integration: string;
  reference: string;
  status: string;
  url?: string | null;
  created_at: string;
  updated_at: string;
  synced_at: string | null;
  sync_error?: string | null;
  metadata: Record<string, unknown>;
}

export interface ReportStorageLocation {
  bucket: string;
  key: string;
  content_type: string;
}

export interface ReportExportResponse {
  report_id: string;
  format: 'html' | 'pdf';
  generated_at: string;
  finding_count: number;
  checksum: string;
  requested_by: string;
  storage: ReportStorageLocation;
  metadata: Record<string, unknown>;
}

export interface ReportExportCollectionResponse {
  data: ReportExportResponse[];
}

export interface AnomalyEvent {
  id: string;
  anomaly_type: string;
  actor: string;
  source: string;
  detected_at: string;
  first_seen: string;
  last_seen: string;
  count: number;
  window_seconds: number;
  metadata: Record<string, unknown>;
}
