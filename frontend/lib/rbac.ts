export const ROLE_ADMIN = 'admin' as const;
export const ROLE_ANALYST = 'analyst' as const;
export const ROLE_FINDINGS_READ = 'findings:read' as const;
export const ROLE_SCANS_READ = 'scans:read' as const;
export const ROLE_SCAN_ENQUEUE = 'scan:enqueue' as const;
export const ROLE_TARGETS_READ = 'targets:read' as const;

export type ControllerRole =
  | typeof ROLE_ADMIN
  | typeof ROLE_ANALYST
  | typeof ROLE_FINDINGS_READ
  | typeof ROLE_SCANS_READ
  | typeof ROLE_SCAN_ENQUEUE
  | typeof ROLE_TARGETS_READ;

export const RBAC_DOCS_URL =
  'https://github.com/medusa-security/Medusa/blob/main/docs/RBAC.md#ui-role-requirements';
