import Link from 'next/link';
import { notFound } from 'next/navigation';
import type { Metadata } from 'next';
import { formatDistanceToNow } from 'date-fns';
import {
  fetchFinding,
  fetchFindingComments,
  fetchFindingTimeline
} from '@/lib/api';
import type { FindingComment, FindingTimelineEvent } from '@/lib/types';
import {
  ROLE_ANALYST,
  ROLE_FINDINGS_READ,
  ROLE_REPORT_EXPORT,
  ROLE_TICKETING_CREATE
} from '@/lib/rbac';
import { StatusBadge } from '@/components/StatusBadge';
import { RequiredRolesNotice } from '@/components/RequiredRolesNotice';
import {
  assignFindingAction,
  updateStatusAction,
  updateTagsAction,
  createCommentAction,
  createJiraTicketAction,
  createGitHubTicketAction
} from './actions';

interface FindingDetailPageProps {
  params: {
    findingId: string;
  };
}

export async function generateMetadata({ params }: FindingDetailPageProps): Promise<Metadata> {
  return {
    title: `Finding ${params.findingId} | Medusa Operations Console`
  };
}

function formatTimestamp(value: string) {
  return formatDistanceToNow(new Date(value), { addSuffix: true });
}

function isNotFoundError(value: unknown): value is string {
  return typeof value === 'string' && value.includes('404');
}

function EvidenceBlock({ value }: { value: string | null | undefined }) {
  if (!value) {
    return <span className="text-xs text-gray-500">Evidence redacted or not provided by scanner.</span>;
  }

  return (
    <pre className="max-h-64 overflow-y-auto rounded-md bg-surface-muted/30 p-3 text-xs text-gray-200">
      {value}
    </pre>
  );
}

function TagsList({ tags }: { tags: string[] }) {
  if (tags.length === 0) {
    return <span className="text-xs text-gray-500">No workflow tags assigned.</span>;
  }

  return (
    <div className="flex flex-wrap gap-2">
      {tags.map((tag) => (
        <span
          key={tag}
          className="rounded-full border border-surface-muted/60 bg-surface-muted/20 px-3 py-1 text-[11px] uppercase tracking-wide text-gray-200"
        >
          {tag}
        </span>
      ))}
    </div>
  );
}

function TimelineEvent({ event }: { event: FindingTimelineEvent }) {
  return (
    <li className="flex gap-3">
      <div className="mt-1 h-2 w-2 flex-shrink-0 rounded-full bg-sky-400" />
      <div className="flex-1 space-y-1">
        <div className="flex items-center justify-between text-xs text-gray-400">
          <span className="font-mono text-gray-300">{event.kind}</span>
          <span>{formatTimestamp(event.created_at)}</span>
        </div>
        <p className="text-sm text-gray-200">{event.actor}</p>
        {event.message ? <p className="text-xs text-gray-400">{event.message}</p> : null}
      </div>
    </li>
  );
}

export default async function FindingDetailPage({ params }: FindingDetailPageProps) {
  let error: string | null = null;

  const finding = await fetchFinding(params.findingId).catch((err) => {
    error = err instanceof Error ? err.message : 'Unable to load finding.';
    return null;
  });

  if (!finding) {
    if (isNotFoundError(error)) {
      notFound();
    }

    return (
      <section className="space-y-4">
        <Link href="/findings" className="text-sm">
          ← Back to findings
        </Link>
        <div className="card border-red-500/40 bg-red-950/40 p-4 text-sm text-red-200">
          {error ?? 'Finding not available.'}
        </div>
      </section>
    );
  }

  const comments = await fetchFindingComments(params.findingId).catch(
    (): FindingComment[] => []
  );
  const timeline = await fetchFindingTimeline(params.findingId).catch(
    (): FindingTimelineEvent[] => []
  );

  const metadataScanner =
    typeof finding.metadata?.['scanner'] === 'string'
      ? (finding.metadata['scanner'] as string)
      : null;
  const scannerValue = metadataScanner ?? finding.scanner;

  return (
    <section className="space-y-6">
      <Link href="/findings" className="text-sm">
        ← Back to findings
      </Link>

      <RequiredRolesNotice
        sections={[
          {
            title: 'Inspect finding details',
            description: 'Grants read-only access to evidence, timeline, and remediation metadata.',
            roles: [ROLE_FINDINGS_READ]
          },
          {
            title: 'Execute workflow changes',
            description: 'Allows assignment updates, status changes, tagging, and analyst commentary.',
            roles: [ROLE_ANALYST]
          },
          {
            title: 'Queue external tickets',
            description: 'Required for creating Jira or GitHub tickets directly from the console.',
            roles: [ROLE_TICKETING_CREATE]
          },
          {
            title: 'Export formal reports',
            description: 'Unlocks deterministic HTML/PDF exports for distribution to stakeholders.',
            roles: [ROLE_REPORT_EXPORT]
          }
        ]}
      />

      <article className="card space-y-5 p-6">
        <header className="space-y-2">
          <p className="text-xs uppercase tracking-[0.3em] text-sky-400">Finding</p>
          <h2 className="text-2xl font-semibold text-white">{finding.title}</h2>
          <div className="flex flex-wrap items-center gap-3">
            <StatusBadge value={finding.severity} />
            <StatusBadge value={finding.status} />
            <span className="rounded-full bg-surface-muted/60 px-2.5 py-0.5 text-xs font-mono text-gray-300">
              Scanner {scannerValue} • Rule {finding.template_id}
            </span>
          </div>
        </header>

        <section className="grid gap-4 md:grid-cols-2">
          <div className="rounded-lg border border-surface-muted/50 bg-surface-muted/20 p-4">
            <h3 className="text-xs font-semibold uppercase tracking-wide text-gray-400">Workflow</h3>
            <dl className="mt-2 space-y-1 text-sm text-gray-200">
              <div className="flex justify-between">
                <dt>Assigned</dt>
                <dd className="font-mono text-gray-300">
                  {finding.assigned_to ?? 'unassigned'}
                </dd>
              </div>
              <div className="flex justify-between">
                <dt>Comments</dt>
                <dd className="font-mono text-gray-300">{finding.comment_count}</dd>
              </div>
              <div className="flex flex-col gap-2 pt-2">
                <TagsList tags={finding.tags} />
              </div>
            </dl>
          </div>
          <div className="rounded-lg border border-surface-muted/50 bg-surface-muted/20 p-4">
            <h3 className="text-xs font-semibold uppercase tracking-wide text-gray-400">Timestamps</h3>
            <dl className="mt-2 space-y-1 text-sm text-gray-200">
              <div className="flex justify-between">
                <dt>Detected</dt>
                <dd className="font-mono text-gray-300">{finding.detected_at}</dd>
              </div>
              <div className="flex justify-between">
                <dt>Updated</dt>
                <dd className="font-mono text-gray-300">{finding.updated_at}</dd>
              </div>
              <div className="flex justify-between">
                <dt>Scan ID</dt>
                <dd className="font-mono text-gray-300">{finding.scan_id}</dd>
              </div>
            </dl>
          </div>
        </section>

        <section className="rounded-lg border border-surface-muted/50 bg-surface-muted/20 p-4">
          <h3 className="text-xs font-semibold uppercase tracking-wide text-gray-400">Evidence</h3>
          <EvidenceBlock value={finding.evidence} />
        </section>

        <section className="rounded-lg border border-surface-muted/50 bg-surface-muted/20 p-4">
          <h3 className="text-xs font-semibold uppercase tracking-wide text-gray-400">Remediation</h3>
          <p className="mt-2 text-sm text-gray-200">
            {finding.remediation ??
              'Remediation guidance will be attached here once enrichment agents generate analyst-approved actions.'}
          </p>
        </section>
      </article>

      <article className="card space-y-4 p-6">
        <h3 className="text-xs font-semibold uppercase tracking-wide text-gray-300">Workflow Controls</h3>
        <div className="grid gap-4 md:grid-cols-2">
          <form action={assignFindingAction} className="flex flex-col gap-2">
            <input type="hidden" name="findingId" value={finding.id} />
            <label className="text-xs uppercase tracking-wide text-gray-400">
              Assign to
              <input
                type="text"
                name="assignee"
                defaultValue={finding.assigned_to ?? ''}
                className="input mt-1"
                placeholder="analyst"
              />
            </label>
            <button type="submit" className="btn btn-primary w-fit text-xs uppercase tracking-wide">
              Update Assignee
            </button>
          </form>
          <form action={updateStatusAction} className="flex flex-col gap-2">
            <input type="hidden" name="findingId" value={finding.id} />
            <label className="text-xs uppercase tracking-wide text-gray-400">
              Status
              <select name="status" defaultValue={finding.status} className="input mt-1">
                <option value="open">open</option>
                <option value="acknowledged">acknowledged</option>
                <option value="resolved">resolved</option>
              </select>
            </label>
            <button type="submit" className="btn btn-secondary w-fit text-xs uppercase tracking-wide">
              Update Status
            </button>
          </form>
        </div>
        <form action={updateTagsAction} className="flex flex-col gap-2 md:w-1/2">
          <input type="hidden" name="findingId" value={finding.id} />
          <label className="text-xs uppercase tracking-wide text-gray-400">
            Tags (comma separated)
            <input
              type="text"
              name="tags"
              defaultValue={finding.tags.join(', ')}
              className="input mt-1"
              placeholder="scope:risk, workflow:triage"
            />
          </label>
          <button type="submit" className="btn btn-tertiary w-fit text-xs uppercase tracking-wide">
            Update Tags
          </button>
        </form>
      </article>

      <article className="card space-y-4 p-6">
        <header className="flex items-center justify-between">
          <h3 className="text-xs font-semibold uppercase tracking-wide text-gray-300">Comments</h3>
          <span className="text-xs text-gray-500">{comments.length} total</span>
        </header>
        <ul className="space-y-3">
          {comments.map((comment) => (
            <li key={comment.id} className="rounded border border-surface-muted/50 bg-surface-muted/20 p-3">
              <header className="flex items-center justify-between text-xs text-gray-400">
                <span className="font-mono text-gray-300">{comment.author}</span>
                <span>{formatTimestamp(comment.created_at)}</span>
              </header>
              <p className="mt-2 text-sm text-gray-200">{comment.message}</p>
            </li>
          ))}
          {comments.length === 0 ? (
            <li className="text-sm text-gray-500">No analyst comments recorded yet.</li>
          ) : null}
        </ul>
        <form action={createCommentAction} className="flex flex-col gap-2">
          <input type="hidden" name="findingId" value={finding.id} />
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
          <button type="submit" className="btn btn-primary w-fit text-xs uppercase tracking-wide">
            Submit Comment
          </button>
        </form>
      </article>

      <article className="card space-y-4 p-6">
        <header className="flex items-center justify-between">
          <h3 className="text-xs font-semibold uppercase tracking-wide text-gray-300">Ticketing</h3>
          <span className="text-xs text-gray-500">{finding.tickets.length} linked</span>
        </header>
        <div className="space-y-2">
          {finding.tickets.length === 0 ? (
            <p className="text-sm text-gray-500">No external tickets recorded yet.</p>
          ) : (
            <ul className="space-y-2">
              {finding.tickets.map((ticket) => (
                <li key={ticket.id} className="flex items-center justify-between rounded border border-surface-muted/50 bg-surface-muted/20 px-3 py-2 text-xs text-gray-300">
                  <span className="font-mono text-gray-200">
                    {ticket.integration}:{ticket.reference}
                  </span>
                  <span>{formatTimestamp(ticket.created_at)}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
        <div className="grid gap-4 md:grid-cols-2">
          <form action={createJiraTicketAction} className="flex flex-col gap-2">
            <input type="hidden" name="findingId" value={finding.id} />
            <h4 className="text-xs uppercase tracking-wide text-gray-400">Create Jira Ticket</h4>
            <input className="input" name="projectKey" placeholder="Project Key" required />
            <input className="input" name="issueType" placeholder="Issue Type" defaultValue="Bug" />
            <input className="input" name="summary" placeholder="Summary" required />
            <textarea className="input" name="description" placeholder="Description" rows={2} />
            <button type="submit" className="btn btn-secondary w-fit text-xs uppercase tracking-wide">
              Queue Jira Ticket
            </button>
          </form>
          <form action={createGitHubTicketAction} className="flex flex-col gap-2">
            <input type="hidden" name="findingId" value={finding.id} />
            <h4 className="text-xs uppercase tracking-wide text-gray-400">Create GitHub Issue</h4>
            <input className="input" name="repository" placeholder="org/repository" required />
            <input className="input" name="title" placeholder="Issue Title" required />
            <textarea className="input" name="body" placeholder="Issue Body" rows={2} />
            <button type="submit" className="btn btn-tertiary w-fit text-xs uppercase tracking-wide">
              Queue GitHub Issue
            </button>
          </form>
        </div>
      </article>

      <article className="card space-y-4 p-6">
        <header className="flex items-center justify-between">
          <h3 className="text-xs font-semibold uppercase tracking-wide text-gray-300">Report Export</h3>
          <span className="text-xs text-gray-500">Deterministic snapshot</span>
        </header>
        <div className="flex flex-wrap gap-3">
          <a
            href={`/api/reports/export?format=pdf&findingId=${finding.id}`}
            className="btn btn-primary text-xs uppercase tracking-wide"
          >
            Download PDF
          </a>
          <a
            href={`/api/reports/export?format=html&findingId=${finding.id}`}
            className="btn btn-secondary text-xs uppercase tracking-wide"
          >
            Download HTML
          </a>
        </div>
      </article>

      <article className="card space-y-4 p-6">
        <h3 className="text-xs font-semibold uppercase tracking-wide text-gray-300">Timeline</h3>
        <ul className="space-y-3">
          {timeline.length === 0 ? (
            <li className="text-sm text-gray-500">No timeline events recorded yet.</li>
          ) : (
            timeline.map((event) => <TimelineEvent key={`${event.kind}-${event.created_at}`} event={event} />)
          )}
        </ul>
      </article>
    </section>
  );
}
