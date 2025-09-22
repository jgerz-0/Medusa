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
import { ROLE_ANALYST, ROLE_REPORT_EXPORT, ROLE_TICKETING_CREATE } from '@/lib/rbac';
import { StatusBadge } from '@/components/StatusBadge';
import { RequiredRolesNotice, type RoleRequirement } from '@/components/RequiredRolesNotice';
import {
  AssignFindingForm,
  UpdateStatusForm,
  UpdateTagsForm,
  CreateCommentForm,
  CreateJiraTicketForm,
  CreateGitHubTicketForm
} from './forms';

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

function formatOptionalTimestamp(value: string | null | undefined) {
  if (!value) {
    return null;
  }

  const parsed = Date.parse(value);
  if (Number.isNaN(parsed)) {
    return null;
  }

  return formatDistanceToNow(new Date(parsed), { addSuffix: true });
}

const SYNC_STALE_MINUTES = 60;

function isSyncStale(syncedAt: string | null | undefined): boolean {
  if (!syncedAt) {
    return true;
  }

  const parsed = Date.parse(syncedAt);
  if (Number.isNaN(parsed)) {
    return true;
  }

  const staleWindowMs = SYNC_STALE_MINUTES * 60 * 1000;
  return Date.now() - parsed > staleWindowMs;
}

function formatTicketMetadataKey(key: string): string {
  if (!key) {
    return key;
  }

  return key
    .split(/[_\s]+/)
    .filter((segment) => segment)
    .map((segment) => segment.charAt(0).toUpperCase() + segment.slice(1))
    .join(' ');
}

function formatTicketMetadataValue(value: unknown): string {
  if (value === null || value === undefined) {
    return '';
  }

  if (typeof value === 'string') {
    return value;
  }

  if (typeof value === 'number' || typeof value === 'boolean') {
    return `${value}`;
  }

  try {
    return JSON.stringify(value);
  } catch (error) {
    return String(value);
  }
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

type StatusBadgeValue = Parameters<typeof StatusBadge>[0]['value'];

const statusBadgeValues = new Set<StatusBadgeValue>([
  'queued',
  'running',
  'completed',
  'failed',
  'open',
  'acknowledged',
  'resolved',
  'critical',
  'high',
  'medium',
  'low',
  'info'
]);

function TicketStatusBadge({ status }: { status: string }) {
  // Normalize casing to ensure consistent badge styling even if integrations vary.
  const normalized = status.toLowerCase();

  if (statusBadgeValues.has(normalized as StatusBadgeValue)) {
    return <StatusBadge value={normalized as StatusBadgeValue} />;
  }

  return (
    <span
      className="inline-flex items-center gap-1 rounded-full border border-surface-muted/60 bg-surface-muted/30 px-2.5 py-0.5 text-xs font-semibold uppercase tracking-wide text-gray-200"
    >
      {/* Preserve the original status label for analyst auditing when unknown. */}
      {status}
    </span>
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

  const roleRequirements: RoleRequirement[] = [
    {
      title: 'Execute workflow edits',
      description:
        'Allows analysts to assign owners, adjust status, retag findings, and record authoritative commentary.',
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
  ];

  return (
    <section className="space-y-6">
      <Link href="/findings" className="text-sm">
        ← Back to findings
      </Link>

      <RequiredRolesNotice
        sections={roleRequirements}
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
          <AssignFindingForm findingId={finding.id} defaultAssignee={finding.assigned_to} />
          <UpdateStatusForm findingId={finding.id} currentStatus={finding.status} />
        </div>
        <UpdateTagsForm
          findingId={finding.id}
          defaultTags={finding.tags.join(', ')}
          className="md:w-1/2"
        />
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
        <CreateCommentForm findingId={finding.id} />
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
              {finding.tickets.map((ticket) => {
                const syncedAtLabel = formatOptionalTimestamp(ticket.synced_at ?? null);
                const syncStale = isSyncStale(ticket.synced_at ?? null);
                const syncError = ticket.sync_error ?? null;
                const metadataEntries = Object.entries(ticket.metadata ?? {}).filter(([, value]) => {
                  if (value === null || value === undefined) {
                    return false;
                  }

                  if (typeof value === 'string') {
                    return value.trim() !== '';
                  }

                  return true;
                });

                return (
                  <li
                    key={ticket.id}
                    className="rounded border border-surface-muted/50 bg-surface-muted/20 px-3 py-2 text-xs text-gray-300"
                  >
                    <div className="flex flex-col gap-2">
                      <div className="flex flex-col gap-1 md:flex-row md:items-center md:justify-between">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="font-mono text-gray-200">
                            {ticket.url ? (
                              <a
                                href={ticket.url}
                                target="_blank"
                                rel="noreferrer noopener"
                                className="underline-offset-2 hover:text-sky-300 hover:underline focus-visible:text-sky-300 focus-visible:underline"
                              >
                                {ticket.integration}:{ticket.reference}
                              </a>
                            ) : (
                              `${ticket.integration}:${ticket.reference}`
                            )}
                          </span>
                          <TicketStatusBadge status={ticket.status} />
                        </div>
                        <span className="text-[11px] uppercase tracking-wide text-gray-500">
                          {formatTimestamp(ticket.created_at)}
                        </span>
                      </div>
                      <div className="flex flex-wrap items-center gap-2 text-[11px] uppercase tracking-wide text-gray-500">
                        <span className="text-gray-400">
                          {syncedAtLabel ? `Synced ${syncedAtLabel}` : 'Awaiting first sync'}
                        </span>
                        {syncStale ? (
                          <span className="rounded-full border border-amber-500/40 bg-amber-500/10 px-2 py-0.5 font-semibold text-amber-300">
                            Stale
                          </span>
                        ) : null}
                        {syncError ? (
                          <span
                            className="rounded-full border border-red-500/40 bg-red-500/10 px-2 py-0.5 font-semibold text-red-300"
                            title={syncError}
                          >
                            Sync Error
                          </span>
                        ) : null}
                      </div>
                      {metadataEntries.length > 0 ? (
                        <dl className="grid gap-x-3 gap-y-1 text-[11px] text-gray-400 sm:grid-cols-[auto,1fr]">
                          {metadataEntries.map(([key, value]) => (
                            <div key={key} className="contents">
                              <dt className="font-semibold uppercase tracking-wide text-gray-500">
                                {formatTicketMetadataKey(key)}
                              </dt>
                              <dd className="text-gray-300">
                                {formatTicketMetadataValue(value)}
                              </dd>
                            </div>
                          ))}
                        </dl>
                      ) : null}
                    </div>
                  </li>
                );
              })}
            </ul>
          )}
        </div>
        <div className="grid gap-4 md:grid-cols-2">
          <CreateJiraTicketForm findingId={finding.id} />
          <CreateGitHubTicketForm findingId={finding.id} />
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
