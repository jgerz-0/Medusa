import type { Metadata } from 'next';
import { fetchFindings, fetchFindingsTimeline } from '@/lib/api';
import type { Finding, FindingsTimelineBucket } from '@/lib/types';
import { FindingsTable } from '@/components/FindingsTable';
import { FindingsFilters } from '@/components/FindingsFilters';
import { FindingsTimeline } from '@/components/FindingsTimeline';
import { RequiredRolesNotice } from '@/components/RequiredRolesNotice';
import { ROLE_ANALYST, ROLE_FINDINGS_READ } from '@/lib/rbac';

export const metadata: Metadata = {
  title: 'Findings | Medusa Operations Console'
};

interface FindingsPageProps {
  searchParams?: {
    scan?: string;
    severity?: string;
    status?: string;
    tag?: string;
    assigned?: string;
    from?: string;
    to?: string;
  };
}

export default async function FindingsPage({ searchParams }: FindingsPageProps) {
  let error: string | null = null;
  let findings: Finding[] = [];
  let timeline: FindingsTimelineBucket[] = [];
  let timelineError: string | null = null;

  const query = {
    scanId: searchParams?.scan,
    severity: searchParams?.severity,
    status: searchParams?.status,
    tag: searchParams?.tag,
    assignedTo: searchParams?.assigned,
    from: searchParams?.from,
    to: searchParams?.to
  };

  try {
    findings = await fetchFindings(query);
  } catch (err) {
    error = err instanceof Error ? err.message : 'Failed to load findings.';
  }

  try {
    timeline = await fetchFindingsTimeline(query);
  } catch (err) {
    timelineError = err instanceof Error ? err.message : 'Failed to load timeline.';
  }

  const hasFilters = Boolean(
    searchParams?.scan ||
      searchParams?.severity ||
      searchParams?.status ||
      searchParams?.tag ||
      searchParams?.assigned ||
      searchParams?.from ||
      searchParams?.to
  );

  return (
    <section className="space-y-4">
      <header className="space-y-2">
        <div>
          <h2 className="text-2xl font-semibold text-white">Findings</h2>
          <p className="text-sm text-gray-400">
            Normalized findings aggregated from controller scans with severity and workflow state metadata.
          </p>
        </div>
        <RequiredRolesNotice
          sections={[
            {
              title: 'View findings and timelines',
              description: 'Required to list normalized findings and trend data from the controller.',
              roles: [ROLE_FINDINGS_READ]
            },
            {
              title: 'Triage and edit findings',
              description: 'Allows acknowledging, reassigning, or tagging findings during incident response.',
              roles: [ROLE_ANALYST]
            }
          ]}
        />
        <FindingsFilters searchParams={searchParams} />
        {hasFilters ? (
          <div className="card border-surface-muted/60 bg-surface-muted/20 px-4 py-3 text-xs text-gray-300">
            <p className="font-semibold uppercase tracking-wide text-gray-400">Active Filters</p>
            <ul className="mt-1 flex flex-wrap gap-2 font-mono">
              {searchParams?.scan && <li>scan_id={searchParams.scan}</li>}
              {searchParams?.severity && <li>severity={searchParams.severity}</li>}
              {searchParams?.status && <li>status={searchParams.status}</li>}
              {searchParams?.tag && <li>tag={searchParams.tag}</li>}
              {searchParams?.assigned && <li>assigned={searchParams.assigned}</li>}
              {searchParams?.from && <li>from={searchParams.from}</li>}
              {searchParams?.to && <li>to={searchParams.to}</li>}
            </ul>
          </div>
        ) : null}
      </header>
      {error ? (
        <div className="card border-red-500/40 bg-red-950/40 p-4 text-sm text-red-200">
          {error}
        </div>
      ) : (
        <FindingsTable findings={findings} />
      )}
      {timelineError ? (
        <div className="card border-red-500/40 bg-red-950/40 p-4 text-sm text-red-200">
          {timelineError}
        </div>
      ) : (
        <FindingsTimeline buckets={timeline} />
      )}
    </section>
  );
}
