'use server';

import { revalidatePath } from 'next/cache';
import {
  assignFinding,
  updateFindingStatus,
  updateFindingTags,
  createFindingComment,
  createJiraTicket,
  createGitHubTicket,
  ControllerError,
  ControllerValidationError
} from '@/lib/api';
import type { FindingStatus } from '@/lib/types';

function parseFindingId(formData: FormData): string {
  const raw = formData.get('findingId');
  if (typeof raw !== 'string') {
    return '';
  }

  return raw.trim();
}

export type ActionState = {
  status: 'idle' | 'success' | 'error';
  message: string | null;
};

function createErrorState(message: string): ActionState {
  return {
    status: 'error',
    message
  };
}

function createSuccessState(message: string): ActionState {
  return {
    status: 'success',
    message
  };
}

function resolveActionError(error: unknown, fallback: string): ActionState {
  if (error instanceof ControllerValidationError || error instanceof ControllerError) {
    return createErrorState(error.message);
  }

  if (error instanceof Error) {
    return createErrorState(error.message);
  }

  return createErrorState(fallback);
}

export function createInitialActionState(): ActionState {
  return { status: 'idle', message: null } satisfies ActionState;
}

export async function assignFindingAction(
  _prevState: ActionState,
  formData: FormData
): Promise<ActionState> {
  const findingId = parseFindingId(formData);
  const assigneeRaw = formData.get('assignee');
  if (!findingId) {
    return createErrorState('Missing finding identifier.');
  }

  if (typeof assigneeRaw !== 'string' || assigneeRaw.trim() === '') {
    return createErrorState('Provide an assignee before updating the workflow.');
  }

  const assignee = assigneeRaw.trim();

  try {
    await assignFinding(findingId, assignee);
    revalidatePath(`/findings/${findingId}`);
    revalidatePath('/findings');
    return createSuccessState('Assignment updated.');
  } catch (error) {
    return resolveActionError(error, 'Unable to update assignment.');
  }
}

export async function updateStatusAction(
  _prevState: ActionState,
  formData: FormData
): Promise<ActionState> {
  const findingId = parseFindingId(formData);
  const statusValue = formData.get('status');
  if (!findingId) {
    return createErrorState('Missing finding identifier.');
  }

  if (typeof statusValue !== 'string' || statusValue.trim() === '') {
    return createErrorState('Select a valid status before updating the workflow.');
  }

  const normalizedStatus = statusValue.trim() as FindingStatus;

  try {
    await updateFindingStatus(findingId, normalizedStatus);
    revalidatePath(`/findings/${findingId}`);
    revalidatePath('/findings');
    return createSuccessState('Status updated.');
  } catch (error) {
    return resolveActionError(error, 'Unable to update status.');
  }
}

export async function updateTagsAction(
  _prevState: ActionState,
  formData: FormData
): Promise<ActionState> {
  const findingId = parseFindingId(formData);
  const tagsRaw = formData.get('tags');
  if (!findingId) {
    return createErrorState('Missing finding identifier.');
  }

  if (typeof tagsRaw !== 'string') {
    return createErrorState('Submit workflow tags as a comma-separated list.');
  }

  const tags = tagsRaw
    .split(',')
    .map((tag) => tag.trim().toLowerCase())
    .filter((tag) => tag.length > 0);

  try {
    await updateFindingTags(findingId, tags);
    revalidatePath(`/findings/${findingId}`);
    revalidatePath('/findings');
    return createSuccessState('Tags updated.');
  } catch (error) {
    return resolveActionError(error, 'Unable to update tags.');
  }
}

export async function createCommentAction(
  _prevState: ActionState,
  formData: FormData
): Promise<ActionState> {
  const findingId = parseFindingId(formData);
  const message = formData.get('message');
  if (!findingId) {
    return createErrorState('Missing finding identifier.');
  }

  if (typeof message !== 'string' || message.trim() === '') {
    return createErrorState('Comment message is required.');
  }

  try {
    await createFindingComment(findingId, message.trim());
    revalidatePath(`/findings/${findingId}`);
    return createSuccessState('Comment recorded.');
  } catch (error) {
    return resolveActionError(error, 'Unable to record comment.');
  }
}

export async function createJiraTicketAction(
  _prevState: ActionState,
  formData: FormData
): Promise<ActionState> {
  const findingId = parseFindingId(formData);
  const projectKey = formData.get('projectKey');
  const issueType = formData.get('issueType');
  const summary = formData.get('summary');
  const description = formData.get('description');
  if (!findingId) {
    return createErrorState('Missing finding identifier.');
  }

  if (typeof projectKey !== 'string' || projectKey.trim() === '') {
    return createErrorState('Project key is required for Jira ticket creation.');
  }

  if (typeof issueType !== 'string' || issueType.trim() === '') {
    return createErrorState('Issue type is required for Jira ticket creation.');
  }

  if (typeof summary !== 'string' || summary.trim() === '') {
    return createErrorState('Summary is required for Jira ticket creation.');
  }

  const payload = {
    findingId,
    projectKey: projectKey.trim(),
    issueType: issueType.trim(),
    summary: summary.trim(),
    description:
      typeof description === 'string' && description.trim() !== ''
        ? description.trim()
        : undefined
  } as const;

  try {
    await createJiraTicket(payload);
    revalidatePath(`/findings/${findingId}`);
    return createSuccessState('Jira ticket queued.');
  } catch (error) {
    return resolveActionError(error, 'Unable to queue Jira ticket.');
  }
}

export async function createGitHubTicketAction(
  _prevState: ActionState,
  formData: FormData
): Promise<ActionState> {
  const findingId = parseFindingId(formData);
  const repository = formData.get('repository');
  const title = formData.get('title');
  const body = formData.get('body');
  if (!findingId) {
    return createErrorState('Missing finding identifier.');
  }

  if (typeof repository !== 'string' || repository.trim() === '') {
    return createErrorState('Repository is required for GitHub issue creation.');
  }

  if (typeof title !== 'string' || title.trim() === '') {
    return createErrorState('Title is required for GitHub issue creation.');
  }

  const payload = {
    findingId,
    repository: repository.trim(),
    title: title.trim(),
    body:
      typeof body === 'string' && body.trim() !== '' ? body.trim() : undefined
  } as const;

  try {
    await createGitHubTicket(payload);
    revalidatePath(`/findings/${findingId}`);
    return createSuccessState('GitHub issue queued.');
  } catch (error) {
    return resolveActionError(error, 'Unable to queue GitHub issue.');
  }
}
