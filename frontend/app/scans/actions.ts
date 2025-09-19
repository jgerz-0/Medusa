'use server';

import { revalidatePath } from 'next/cache';
import {
  ControllerValidationError,
  createScan,
  type CreateScanPayload,
  type ValidationIssue
} from '@/lib/api';

export type SupportedScanner = 'nuclei' | 'zap' | 'sqlmap';

const ALLOWED_SCANNERS: SupportedScanner[] = ['nuclei', 'zap', 'sqlmap'];
const ALLOWED_ZAP_POLICIES = ['baseline', 'full'] as const;
const ALLOWED_ZAP_MODES = ['baseline', 'full'] as const;
const ALLOWED_SQLMAP_LEVELS = [1, 2, 3, 4, 5] as const;
const ALLOWED_SQLMAP_RISKS = [0, 1, 2, 3] as const;

export interface ScheduleScanInput {
  targetId: string;
  /** Optional hint used for client-side validation mirrors controller guardrails. */
  targetScope?: string;
  scanner: SupportedScanner;
  parameters?: Record<string, unknown>;
}

export interface ScheduleScanResult {
  ok: boolean;
  message: string;
  issues?: ValidationIssue[];
}

function normalizeHosts(hosts: string[]): string[] {
  const seen = new Set<string>();
  const sanitized: string[] = [];

  for (const value of hosts) {
    if (typeof value !== 'string') {
      continue;
    }

    const trimmed = value.trim();
    if (!trimmed || seen.has(trimmed)) {
      continue;
    }

    seen.add(trimmed);
    sanitized.push(trimmed);
  }

  return sanitized;
}

function isHttpScope(scope: string | undefined): boolean {
  if (!scope) {
    return true;
  }

  const normalized = scope.trim().toLowerCase();
  return normalized.startsWith('http://') || normalized.startsWith('https://');
}

function sanitizeRateLimit(value: unknown, fallback: string): string {
  let numeric: number | null = null;
  if (typeof value === 'number') {
    numeric = value;
  } else if (typeof value === 'string') {
    const trimmed = value.trim();
    if (!trimmed) {
      return fallback;
    }
    const parsed = Number(trimmed);
    if (!Number.isNaN(parsed)) {
      numeric = parsed;
    }
  }

  if (numeric === null || !Number.isFinite(numeric) || numeric <= 0) {
    return fallback;
  }

  const normalized = numeric.toFixed(2).replace(/\.00$/, '').replace(/(\.\d+?)0+$/, '$1');
  return normalized;
}

export async function scheduleScanAction(
  input: ScheduleScanInput
): Promise<ScheduleScanResult> {
  const issues: ValidationIssue[] = [];

  if (!input.targetId) {
    issues.push({ field: 'targetId', message: 'Select a target within the authorized scope.' });
  }

  if (!input.scanner) {
    issues.push({ field: 'scanner', message: 'Choose a scanner to execute.' });
  } else if (!ALLOWED_SCANNERS.includes(input.scanner)) {
    issues.push({
      field: 'scanner',
      message: 'Unsupported scanner. Choose nuclei, ZAP, or SQLMap.'
    });
  }

  const sanitizedParameters: Record<string, unknown> = {};
  const rawParameters = input.parameters ?? {};

  if (input.scanner === 'nuclei') {
    const profileValue = typeof rawParameters.profile === 'string' ? rawParameters.profile.trim() : '';
    if (!profileValue) {
      issues.push({ field: 'profile', message: 'Choose a scan profile preset.' });
    } else {
      sanitizedParameters.profile = profileValue;
    }

    const hosts = Array.isArray(rawParameters.requested_hosts)
      ? rawParameters.requested_hosts
      : Array.isArray(rawParameters.requestedHosts)
        ? rawParameters.requestedHosts
        : [];
    const normalizedHosts = normalizeHosts(hosts as string[]);
    if (normalizedHosts.length > 0) {
      sanitizedParameters.requested_hosts = normalizedHosts;
    }
  } else if (input.scanner === 'zap') {
    if (!isHttpScope(input.targetScope)) {
      issues.push({
        field: 'targetId',
        message: 'ZAP scans require an HTTP or HTTPS target scope.'
      });
    }

    const policy = typeof rawParameters.policy === 'string' ? rawParameters.policy.trim().toLowerCase() : '';
    if (!ALLOWED_ZAP_POLICIES.includes(policy as (typeof ALLOWED_ZAP_POLICIES)[number])) {
      issues.push({ field: 'policy', message: 'ZAP policy must be baseline or full.' });
    } else {
      sanitizedParameters.policy = policy;
    }

    const mode = typeof rawParameters.mode === 'string' ? rawParameters.mode.trim().toLowerCase() : '';
    if (!ALLOWED_ZAP_MODES.includes(mode as (typeof ALLOWED_ZAP_MODES)[number])) {
      issues.push({ field: 'mode', message: 'ZAP mode must be baseline or full.' });
    } else {
      sanitizedParameters.mode = mode;
    }

    const rateLimit = sanitizeRateLimit(rawParameters.rate_limit, '5');
    sanitizedParameters.rate_limit = rateLimit;

    if (typeof rawParameters.ajax_spider === 'boolean') {
      sanitizedParameters.ajax_spider = rawParameters.ajax_spider;
    }
  } else if (input.scanner === 'sqlmap') {
    if (!isHttpScope(input.targetScope)) {
      issues.push({
        field: 'targetId',
        message: 'SQLMap scans require an HTTP or HTTPS target scope.'
      });
    }

    const levelCandidate = Number(rawParameters.level);
    if (!Number.isInteger(levelCandidate) || !ALLOWED_SQLMAP_LEVELS.includes(levelCandidate as number)) {
      issues.push({ field: 'level', message: 'SQLMap level must be between 1 and 5.' });
    } else {
      sanitizedParameters.level = levelCandidate;
    }

    const riskCandidate = Number(rawParameters.risk);
    if (!Number.isInteger(riskCandidate) || !ALLOWED_SQLMAP_RISKS.includes(riskCandidate as number)) {
      issues.push({ field: 'risk', message: 'SQLMap risk must be between 0 and 3.' });
    } else {
      sanitizedParameters.risk = riskCandidate;
    }

    if (rawParameters.request_delay !== undefined) {
      sanitizedParameters.request_delay = sanitizeRateLimit(rawParameters.request_delay, '0');
    }
  }

  if (issues.length > 0) {
    return {
      ok: false,
      message: 'Scan request is incomplete. Resolve the highlighted fields and retry.',
      issues
    };
  }

  const payload: CreateScanPayload = {
    target_id: input.targetId,
    scanner: input.scanner,
    parameters: sanitizedParameters
  };

  try {
    const scan = await createScan(payload);
    revalidatePath('/scans');
    const descriptor = scan.target || 'selected target';
    return {
      ok: true,
      message: `Scan queued for ${descriptor}.`
    };
  } catch (error) {
    if (error instanceof ControllerValidationError) {
      return {
        ok: false,
        message: error.message,
        issues: error.issues
      };
    }

    const fallback = error instanceof Error ? error.message : 'Failed to schedule scan.';
    return {
      ok: false,
      message: fallback
    };
  }
}
