'use client';

import { useFormState, useFormStatus } from 'react-dom';
import {
  assignFindingAction,
  updateStatusAction,
  updateTagsAction,
  createCommentAction,
  createJiraTicketAction,
  createGitHubTicketAction,
  createInitialActionState,
  type ActionState
} from './actions';
import type { FindingStatus } from '@/lib/types';

function mergeClasses(...classes: (string | undefined)[]): string {
  return classes.filter(Boolean).join(' ');
}

function FormAlert({ state }: { state: ActionState }) {
  if (state.status === 'idle' || !state.message) {
    return null;
  }

  const className =
    state.status === 'success'
      ? 'rounded border border-emerald-500/40 bg-emerald-950/40 px-3 py-2 text-xs text-emerald-200'
      : 'rounded border border-red-500/40 bg-red-950/40 px-3 py-2 text-xs text-red-200';

  return <div className={className}>{state.message}</div>;
}

function SubmitButton({
  idleLabel,
  pendingLabel,
  className
}: {
  idleLabel: string;
  pendingLabel: string;
  className: string;
}) {
  const { pending } = useFormStatus();

  return (
    <button
      type="submit"
      className={className}
      disabled={pending}
      aria-disabled={pending}
    >
      {pending ? pendingLabel : idleLabel}
    </button>
  );
}

export function AssignFindingForm({
  findingId,
  defaultAssignee,
  className
}: {
  findingId: string;
  defaultAssignee: string | null;
  className?: string;
}) {
  const [state, formAction] = useFormState(assignFindingAction, createInitialActionState());

  return (
    <form action={formAction} className={mergeClasses('flex flex-col gap-2', className)}>
      <input type="hidden" name="findingId" value={findingId} />
      <label className="text-xs uppercase tracking-wide text-gray-400">
        Assign to
        <input
          type="text"
          name="assignee"
          defaultValue={defaultAssignee ?? ''}
          className="input mt-1"
          placeholder="analyst"
        />
      </label>
      <SubmitButton
        idleLabel="Update Assignee"
        pendingLabel="Updating..."
        className="btn btn-primary w-fit text-xs uppercase tracking-wide"
      />
      <FormAlert state={state} />
    </form>
  );
}

export function UpdateStatusForm({
  findingId,
  currentStatus,
  className
}: {
  findingId: string;
  currentStatus: FindingStatus;
  className?: string;
}) {
  const [state, formAction] = useFormState(updateStatusAction, createInitialActionState());

  return (
    <form action={formAction} className={mergeClasses('flex flex-col gap-2', className)}>
      <input type="hidden" name="findingId" value={findingId} />
      <label className="text-xs uppercase tracking-wide text-gray-400">
        Status
        <select name="status" defaultValue={currentStatus} className="input mt-1">
          <option value="open">open</option>
          <option value="acknowledged">acknowledged</option>
          <option value="resolved">resolved</option>
        </select>
      </label>
      <SubmitButton
        idleLabel="Update Status"
        pendingLabel="Updating..."
        className="btn btn-secondary w-fit text-xs uppercase tracking-wide"
      />
      <FormAlert state={state} />
    </form>
  );
}

export function UpdateTagsForm({
  findingId,
  defaultTags,
  className
}: {
  findingId: string;
  defaultTags: string;
  className?: string;
}) {
  const [state, formAction] = useFormState(updateTagsAction, createInitialActionState());

  return (
    <form action={formAction} className={mergeClasses('flex flex-col gap-2', className)}>
      <input type="hidden" name="findingId" value={findingId} />
      <label className="text-xs uppercase tracking-wide text-gray-400">
        Tags (comma separated)
        <input
          type="text"
          name="tags"
          defaultValue={defaultTags}
          className="input mt-1"
          placeholder="scope:risk, workflow:triage"
        />
      </label>
      <SubmitButton
        idleLabel="Update Tags"
        pendingLabel="Updating..."
        className="btn btn-tertiary w-fit text-xs uppercase tracking-wide"
      />
      <FormAlert state={state} />
    </form>
  );
}

export function CreateCommentForm({ findingId }: { findingId: string }) {
  const [state, formAction] = useFormState(createCommentAction, createInitialActionState());

  return (
    <form action={formAction} className="flex flex-col gap-2">
      <input type="hidden" name="findingId" value={findingId} />
      <label className="text-xs uppercase tracking-wide text-gray-400">
        Add Comment
        <textarea
          name="message"
          rows={3}
          className="input mt-1"
          placeholder="Document analyst observations or next steps"
          required
        />
      </label>
      <SubmitButton
        idleLabel="Submit Comment"
        pendingLabel="Submitting..."
        className="btn btn-primary w-fit text-xs uppercase tracking-wide"
      />
      <FormAlert state={state} />
    </form>
  );
}

export function CreateJiraTicketForm({ findingId }: { findingId: string }) {
  const [state, formAction] = useFormState(createJiraTicketAction, createInitialActionState());

  return (
    <form action={formAction} className="flex flex-col gap-2">
      <input type="hidden" name="findingId" value={findingId} />
      <h4 className="text-xs uppercase tracking-wide text-gray-400">Create Jira Ticket</h4>
      <input className="input" name="projectKey" placeholder="Project Key" required />
      <input className="input" name="issueType" placeholder="Issue Type" defaultValue="Bug" required />
      <input className="input" name="summary" placeholder="Summary" required />
      <textarea className="input" name="description" placeholder="Description" rows={2} />
      <SubmitButton
        idleLabel="Queue Jira Ticket"
        pendingLabel="Queueing..."
        className="btn btn-secondary w-fit text-xs uppercase tracking-wide"
      />
      <FormAlert state={state} />
    </form>
  );
}

export function CreateGitHubTicketForm({ findingId }: { findingId: string }) {
  const [state, formAction] = useFormState(createGitHubTicketAction, createInitialActionState());

  return (
    <form action={formAction} className="flex flex-col gap-2">
      <input type="hidden" name="findingId" value={findingId} />
      <h4 className="text-xs uppercase tracking-wide text-gray-400">Create GitHub Issue</h4>
      <input className="input" name="repository" placeholder="org/repository" required />
      <input className="input" name="title" placeholder="Issue Title" required />
      <textarea className="input" name="body" placeholder="Issue Body" rows={2} />
      <SubmitButton
        idleLabel="Queue GitHub Issue"
        pendingLabel="Queueing..."
        className="btn btn-tertiary w-fit text-xs uppercase tracking-wide"
      />
      <FormAlert state={state} />
    </form>
  );
}
