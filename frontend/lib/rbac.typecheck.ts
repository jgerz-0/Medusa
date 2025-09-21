import type { ControllerRole } from '@/lib/rbac';
import {
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
} from '@/lib/rbac';

// Utility types for compile-time equality checks.
type Expect<T extends true> = T;
type Equal<A, B> = (<T>() => T extends A ? 1 : 2) extends (<T>() => T extends B ? 1 : 2)
  ? true
  : false;

type BackendRoles =
  | typeof ROLE_ADMIN
  | typeof ROLE_ANALYST
  | typeof ROLE_FINDINGS_READ
  | typeof ROLE_SCANS_READ
  | typeof ROLE_SCAN_ENQUEUE
  | typeof ROLE_BINARY_PREPROCESS_ENQUEUE
  | typeof ROLE_BINARY_STATIC_ANALYSIS_ENQUEUE
  | typeof ROLE_BINARY_FUZZING_ENQUEUE
  | typeof ROLE_BINARY_SYMBOLIC_EXECUTION_ENQUEUE
  | typeof ROLE_TARGETS_READ
  | typeof ROLE_TARGETS_WRITE
  | typeof ROLE_ENRICHMENT_ENQUEUE
  | typeof ROLE_VALIDATION_ENQUEUE
  | typeof ROLE_REPORT_EXPORT
  | typeof ROLE_TICKETING_CREATE
  | typeof ROLE_RECON_ENQUEUE;

type _ControllerMatchesBackend = Expect<Equal<ControllerRole, BackendRoles>>;
