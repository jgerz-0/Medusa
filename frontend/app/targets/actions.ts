'use server';

import { revalidatePath } from 'next/cache';
import {
  ControllerError,
  ControllerValidationError,
  createTarget,
  type CreateTargetPayload,
  type ValidationIssue
} from '@/lib/api';

export interface CreateTargetState {
  status: 'idle' | 'success' | 'error';
  message: string;
  issues: ValidationIssue[];
  shouldReset: boolean;
}

export const initialCreateTargetState: CreateTargetState = {
  status: 'idle',
  message: '',
  issues: [],
  shouldReset: false
};

function normalizeText(value: FormDataEntryValue | null): string {
  if (typeof value !== 'string') {
    return '';
  }
  return value.trim();
}

function parseAuthorization(value: FormDataEntryValue | null): boolean {
  if (value === null) {
    return false;
  }

  if (typeof value === 'string') {
    const normalized = value.trim().toLowerCase();
    return normalized === 'true' || normalized === '1' || normalized === 'on';
  }

  return Boolean(value);
}

export async function createTargetAction(
  _prevState: CreateTargetState,
  formData: FormData
): Promise<CreateTargetState> {
  const issues: ValidationIssue[] = [];

  const name = normalizeText(formData.get('name'));
  if (!name) {
    issues.push({ field: 'name', message: 'Provide a friendly name for the asset.' });
  }

  const scope = normalizeText(formData.get('scope'));
  if (!scope) {
    issues.push({ field: 'scope', message: 'Define the explicit engagement scope for this target.' });
  }

  const isAuthorized = parseAuthorization(formData.get('is_authorized'));

  if (issues.length > 0) {
    return {
      status: 'error',
      message: 'Target registration is incomplete. Resolve the highlighted fields and retry.',
      issues,
      shouldReset: false
    };
  }

  const payload: CreateTargetPayload = {
    name,
    scope,
    is_authorized: isAuthorized
  };

  try {
    await createTarget(payload);
    revalidatePath('/targets');
    revalidatePath('/scans');

    return {
      status: 'success',
      message: `Target ${name} registered and ready for scanning.`,
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

    const fallbackMessage =
      error instanceof ControllerError
        ? error.message
        : error instanceof Error
          ? error.message
          : 'Failed to register target with controller.';

    return {
      status: 'error',
      message: fallbackMessage,
      issues: [],
      shouldReset: false
    };
  }
}
