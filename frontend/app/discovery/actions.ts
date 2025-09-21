'use server';

import { revalidatePath } from 'next/cache';
import {
  ControllerError,
  ControllerValidationError,
  promoteDiscovery,
  type ValidationIssue
} from '@/lib/api';

export interface PromoteDiscoveryState {
  status: 'idle' | 'success' | 'error';
  message: string;
  issues: ValidationIssue[];
  shouldReset: boolean;
}

export const initialPromoteDiscoveryState: PromoteDiscoveryState = {
  status: 'idle',
  message: '',
  issues: [],
  shouldReset: false
};

export async function promoteDiscoveryAction(
  _prevState: PromoteDiscoveryState,
  formData: FormData
): Promise<PromoteDiscoveryState> {
  const issues: ValidationIssue[] = [];

  const discoveryId = formData.get('discoveryId');
  const targetName = formData.get('targetName');
  const scope = formData.get('scope');

  const normalizedDiscoveryId = typeof discoveryId === 'string' ? discoveryId.trim() : '';
  const normalizedTargetName = typeof targetName === 'string' ? targetName.trim() : '';
  const normalizedScope = typeof scope === 'string' ? scope.trim() : '';

  if (!normalizedDiscoveryId) {
    issues.push({
      field: 'discoveryId',
      message: 'Choose a discovery emitted by the recon worker.'
    });
  }

  if (!normalizedTargetName) {
    issues.push({
      field: 'targetName',
      message: 'Provide a descriptive target name for auditing.'
    });
  }

  if (issues.length > 0) {
    return {
      status: 'error',
      message: 'Promotion request is incomplete. Resolve the highlighted fields and retry.',
      issues,
      shouldReset: false
    };
  }

  try {
    await promoteDiscovery({
      discoveryId: normalizedDiscoveryId,
      targetName: normalizedTargetName,
      scope: normalizedScope || undefined
    });

    revalidatePath('/discovery');
    revalidatePath('/targets');

    return {
      status: 'success',
      message: 'Discovery promoted. Target registry has been refreshed.',
      issues: [],
      shouldReset: true
    };
  } catch (error) {
    if (error instanceof ControllerValidationError) {
      return {
        status: 'error',
        message: error.message,
        issues: error.issues,
        shouldReset: false
      };
    }

    const message = error instanceof ControllerError ? error.message : 'Failed to promote discovery.';

    return {
      status: 'error',
      message,
      issues: [],
      shouldReset: false
    };
  }
}
