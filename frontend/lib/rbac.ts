// Role identifiers must stay aligned with controller/main.py. Update both sides
// whenever the backend exposes new RBAC scopes.
export const ROLE_ADMIN = 'admin' as const;
export const ROLE_ANALYST = 'analyst' as const;
export const ROLE_FINDINGS_READ = 'findings:read' as const;
export const ROLE_SCANS_READ = 'scans:read' as const;
export const ROLE_SCAN_ENQUEUE = 'scan:enqueue' as const;
export const ROLE_BINARY_PREPROCESS_ENQUEUE = 'binary:preprocess' as const;
export const ROLE_BINARY_STATIC_ANALYSIS_ENQUEUE = 'binary:static-analysis' as const;
export const ROLE_BINARY_FUZZING_ENQUEUE = 'binary:fuzzing' as const;
export const ROLE_BINARY_SYMBOLIC_EXECUTION_ENQUEUE = 'binary:symbolic-execution' as const;
export const ROLE_TARGETS_READ = 'targets:read' as const;
export const ROLE_TARGETS_WRITE = 'targets:write' as const;
export const ROLE_ENRICHMENT_ENQUEUE = 'enrich:enqueue' as const;
export const ROLE_VALIDATION_ENQUEUE = 'validation:enqueue' as const;
export const ROLE_REPORT_EXPORT = 'report:export' as const;
export const ROLE_TICKETING_CREATE = 'ticket:create' as const;
export const ROLE_RECON_ENQUEUE = 'recon:enqueue' as const;

export const CONTROLLER_ROLES = [
  ROLE_ADMIN,
  ROLE_ANALYST,
  ROLE_FINDINGS_READ,
  ROLE_SCANS_READ,
  ROLE_SCAN_ENQUEUE,
  ROLE_BINARY_PREPROCESS_ENQUEUE,
  ROLE_BINARY_STATIC_ANALYSIS_ENQUEUE,
  ROLE_BINARY_FUZZING_ENQUEUE,
  ROLE_BINARY_SYMBOLIC_EXECUTION_ENQUEUE,
  ROLE_TARGETS_READ,
  ROLE_TARGETS_WRITE,
  ROLE_ENRICHMENT_ENQUEUE,
  ROLE_VALIDATION_ENQUEUE,
  ROLE_REPORT_EXPORT,
  ROLE_TICKETING_CREATE,
  ROLE_RECON_ENQUEUE
] as const;

export type ControllerRole = (typeof CONTROLLER_ROLES)[number];

export const RBAC_DOCS_URL =
  'https://github.com/medusa-security/Medusa/blob/main/docs/RBAC.md#ui-role-requirements';
