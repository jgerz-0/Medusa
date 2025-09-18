'use server';

import { revalidatePath } from 'next/cache';
import {
  ControllerValidationError,
  createScan,
  type CreateScanPayload,
  type ValidationIssue
} from '@/lib/api';

export interface ScheduleScanInput {
  targetId: string;
  profile: string;
  requestedHosts: string[];
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

export async function scheduleScanAction(
  input: ScheduleScanInput
): Promise<ScheduleScanResult> {
  const issues: ValidationIssue[] = [];

  if (!input.targetId) {
    issues.push({ field: 'targetId', message: 'Select a target within the authorized scope.' });
  }

  if (!input.profile) {
    issues.push({ field: 'profile', message: 'Choose a scan profile preset.' });
  }

  if (issues.length > 0) {
    return {
      ok: false,
      message: 'Scan request is incomplete. Resolve the highlighted fields and retry.',
      issues
    };
  }

  const hosts = normalizeHosts(input.requestedHosts);
  const parameters: Record<string, unknown> = {
    profile: input.profile
  };
  if (hosts.length > 0) {
    parameters.requested_hosts = hosts;
  }

  const payload: CreateScanPayload = {
    target_id: input.targetId,
    scanner: 'nuclei',
    parameters
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
