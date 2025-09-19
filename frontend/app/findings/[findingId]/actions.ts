'use server';

import { revalidatePath } from 'next/cache';
import {
  assignFinding,
  updateFindingStatus,
  updateFindingTags,
  createFindingComment,
  createJiraTicket,
  createGitHubTicket
} from '@/lib/api';
import type { FindingStatus } from '@/lib/types';

function parseFindingId(formData: FormData): string {
  const raw = formData.get('findingId');
  return typeof raw === 'string' ? raw : '';
}

export async function assignFindingAction(formData: FormData) {
  const findingId = parseFindingId(formData);
  const assigneeRaw = formData.get('assignee');
  if (!findingId || typeof assigneeRaw !== 'string') {
    return;
  }

  await assignFinding(findingId, assigneeRaw);
  revalidatePath(`/findings/${findingId}`);
  revalidatePath('/findings');
}

export async function updateStatusAction(formData: FormData) {
  const findingId = parseFindingId(formData);
  const statusValue = formData.get('status');
  if (!findingId || typeof statusValue !== 'string') {
    return;
  }

  await updateFindingStatus(findingId, statusValue as FindingStatus);
  revalidatePath(`/findings/${findingId}`);
  revalidatePath('/findings');
}

export async function updateTagsAction(formData: FormData) {
  const findingId = parseFindingId(formData);
  const tagsRaw = formData.get('tags');
  if (!findingId || typeof tagsRaw !== 'string') {
    return;
  }

  const tags = tagsRaw
    .split(',')
    .map((tag) => tag.trim().toLowerCase())
    .filter((tag) => tag.length > 0);

  await updateFindingTags(findingId, tags);
  revalidatePath(`/findings/${findingId}`);
  revalidatePath('/findings');
}

export async function createCommentAction(formData: FormData) {
  const findingId = parseFindingId(formData);
  const message = formData.get('message');
  if (!findingId || typeof message !== 'string') {
    return;
  }

  await createFindingComment(findingId, message);
  revalidatePath(`/findings/${findingId}`);
}

export async function createJiraTicketAction(formData: FormData) {
  const findingId = parseFindingId(formData);
  const projectKey = formData.get('projectKey');
  const issueType = formData.get('issueType');
  const summary = formData.get('summary');
  const description = formData.get('description');
  if (
    !findingId ||
    typeof projectKey !== 'string' ||
    typeof issueType !== 'string' ||
    typeof summary !== 'string'
  ) {
    return;
  }

  await createJiraTicket({
    findingId,
    projectKey,
    issueType,
    summary,
    description: typeof description === 'string' ? description : undefined
  });
  revalidatePath(`/findings/${findingId}`);
}

export async function createGitHubTicketAction(formData: FormData) {
  const findingId = parseFindingId(formData);
  const repository = formData.get('repository');
  const title = formData.get('title');
  const body = formData.get('body');
  if (!findingId || typeof repository !== 'string' || typeof title !== 'string') {
    return;
  }

  await createGitHubTicket({
    findingId,
    repository,
    title,
    body: typeof body === 'string' ? body : undefined
  });
  revalidatePath(`/findings/${findingId}`);
}
