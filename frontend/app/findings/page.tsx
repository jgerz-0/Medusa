import { Suspense } from 'react';
import type { Metadata } from 'next';
import { fetchFindings, fetchFindingsTimeline, fetchReportExports } from '@/lib/api';
import type { ReportExportResponse } from '@/lib/types';
import { FindingsTable } from '@/components/FindingsTable';
import { FindingsFilters } from '@/components/FindingsFilters';
import { FindingsTimeline } from '@/components/FindingsTimeline';
import { RequiredRolesNotice } from '@/components/RequiredRolesNotice';
import { ROLE_ANALYST, ROLE_FINDINGS_READ } from '@/lib/rbac';
import type { SearchParamsInput } from '@/lib/searchParams';
import { FindingsTableSkeleton, FindingsTimelineSkeleton } from './loading';

type FindingsQueryState = Parameters<typeof fetchFindings>[0];
type FindingsTimelineQueryState = Parameters<typeof fetchFindingsTimeline>[0];

export const metadata: Metadata = {
  title: 'Findings | Medusa Operations Console'
};

interface FindingsPageProps {
  searchParams?: SearchParamsInput;
}

function parsePositiveInteger(value: string | string[] | undefined, fallback: number): number {
  const raw = Array.isArray(value) ? value[0] : value;
  if (typeof raw !== 'string') {
    return fallback;
  }

  const parsed = Number.parseInt(raw, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

async function FindingsTableBoundary(props?: {
  query: FindingsQueryState;
  searchParams?: SearchParamsInput;
}) {
  if (!props || !props.query) {
    return (
      <div className="card border-red-500/40 bg-red-950/40 p-4 text-sm text-red-200" role="alert">
        Failed to load findings.
      </div>
    );
  }

  const { query, searchParams } = props;

  try {
    const findingsResponse = await fetchFindings(query);
    return (
      <FindingsTable
        findings={findingsResponse.data ?? []}
        pagination={findingsResponse.pagination ?? undefined}
        searchParams={searchParams}
      />
    );
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Failed to load findings.';
    return (
      <div className="card border-red-500/40 bg-red-950/40 p-4 text-sm text-red-200" role="alert">
        {message}
      </div>
    );
  }
}

async function FindingsTimelineBoundary(props?: { query: FindingsTimelineQueryState }) {
  if (!props || !props.query) {
    return (
      <div className="card border-red-500/40 bg-red-950/40 p-4 text-sm text-red-200" role="alert">
        Failed to load timeline.
      </div>
    );
  }

  const { query } = props;

  try {
    const timeline = await fetchFindingsTimeline(query);
    return <FindingsTimeline buckets={timeline} />;
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Failed to load timeline.';
    return (
      <div className="card border-red-500/40 bg-red-950/40 p-4 text-sm text-red-200" role="alert">
        {message}
      </div>
    );
  }
}

interface FindingsExportsBoundaryProps {
  scanId?: string;
}

async function FindingsExportsBoundary({ scanId }: FindingsExportsBoundaryProps = {}) {
  let recentExports: ReportExportResponse[] = [];
  try {
    recentExports = await fetchReportExports({
      scanId,
      limit: 5
    });
  } catch {
    recentExports = [];
  }

  if (recentExports.length === 0) {
    return null;
  }

  return (
    <div className="w-full max-w-sm rounded border border-surface-muted/40 bg-surface-muted/10 p-3">
      <h4 className="text-[10px] font-semibold uppercase tracking-wide text-gray-400">Recent exports</h4>
      <ul className="mt-2 space-y-1">
        {recentExports.map((record) => (
          <li key={record.report_id} className="flex items-center justify-between gap-2 text-[11px] text-gray-300">
            <span className="font-mono text-[10px] text-gray-500">
              {record.report_id.slice(0, 8)} • {record.format.toUpperCase()} • {new Date(record.generated_at).toLocaleString()}
            </span>
            <a
              href={`/api/reports/export?reportId=${record.report_id}&format=${record.format}`}
              className="text-[10px] font-semibold uppercase tracking-wide text-sky-400 hover:text-sky-300"
            >
              Download
            </a>
          </li>
        ))}
      </ul>
    </div>
  );
}

export default function FindingsPage({ searchParams }: FindingsPageProps) {
  const page = parsePositiveInteger(searchParams?.page, 1);
  const pageSize = parsePositiveInteger(searchParams?.page_size, 50);

  const normalizedSeverity =
    typeof searchParams?.severity === 'string' ? searchParams.severity.toLowerCase() : undefined;
  const normalizedStatus =
    typeof searchParams?.status === 'string' ? searchParams.status.toLowerCase() : undefined;
  const normalizedScope =
    typeof searchParams?.scope === 'string' ? searchParams.scope.toLowerCase() : undefined;

  const filterParams = {
    scan: typeof searchParams?.scan === 'string' ? searchParams?.scan : undefined,
    severity: normalizedSeverity,
    status: normalizedStatus,
    scope: normalizedScope,
    tag: typeof searchParams?.tag === 'string' ? searchParams?.tag : undefined,
    assigned: typeof searchParams?.assigned === 'string' ? searchParams?.assigned : undefined,
    from: typeof searchParams?.from === 'string' ? searchParams?.from : undefined,
    to: typeof searchParams?.to === 'string' ? searchParams?.to : undefined
  } satisfies Record<string, string | undefined>;

  const query: FindingsQueryState = {
    scanId: filterParams.scan,
    severity: filterParams.severity,
    status: filterParams.status,
    scope: filterParams.scope,
    tag: filterParams.tag,
    assignedTo: filterParams.assigned,
    from: filterParams.from,
    to: filterParams.to,
    page,
    pageSize
  };

  const timelineQuery: FindingsTimelineQueryState = {
    scanId: query.scanId,
    severity: query.severity,
    status: query.status,
    scope: query.scope,
    tag: query.tag,
    assignedTo: query.assignedTo,
    from: query.from,
    to: query.to
  };

  const hasFilters = Boolean(
    filterParams.scan ||
      filterParams.severity ||
      filterParams.status ||
      filterParams.scope ||
      filterParams.tag ||
      filterParams.assigned ||
      filterParams.from ||
      filterParams.to
  );

  const exportParams = new URLSearchParams();
  if (query.scanId) {
    exportParams.set('scanId', query.scanId);
  }
  if (query.severity) {
    exportParams.set('severity', query.severity);
  }
  if (query.status) {
    exportParams.set('status', query.status);
  }
  if (query.scope) {
    exportParams.set('scope', query.scope);
  }
  if (query.tag) {
    exportParams.set('tag', query.tag);
  }
  if (query.assignedTo) {
    exportParams.set('assigned', query.assignedTo);
  }
  if (query.from) {
    exportParams.set('from', query.from);
  }
  if (query.to) {
    exportParams.set('to', query.to);
  }

  const exportEnabled = Array.from(exportParams.keys()).length > 0;

  function buildExportHref(format: 'pdf' | 'html'): string {
    const params = new URLSearchParams(exportParams);
    params.set('format', format);
    const queryString = params.toString();
    return `/api/reports/export?${queryString}`;
  }

  return (
    <section className="space-y-4">
      <header className="space-y-2">
        <div className="flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
          <div>
            <h2 className="text-2xl font-semibold text-white">Findings</h2>
            <p className="text-sm text-gray-400">
              Normalized findings aggregated from controller scans with severity and workflow state metadata.
            </p>
          </div>
          <div className="flex flex-col items-start gap-2 md:items-end">
            <div className="flex flex-wrap gap-2">
              <a
                href={exportEnabled ? buildExportHref('pdf') : '#'}
                aria-disabled={!exportEnabled}
                className={`btn btn-primary text-xs uppercase tracking-wide${
                  exportEnabled ? '' : ' cursor-not-allowed opacity-60'
                }`}
              >
                Export PDF
              </a>
              <a
                href={exportEnabled ? buildExportHref('html') : '#'}
                aria-disabled={!exportEnabled}
                className={`btn btn-secondary text-xs uppercase tracking-wide${
                  exportEnabled ? '' : ' cursor-not-allowed opacity-60'
                }`}
              >
                Export HTML
              </a>
            </div>
            <p className="text-[11px] uppercase tracking-wide text-gray-500">
              {exportEnabled
                ? 'Exports respect the active filters applied to this view.'
                : 'Apply filters or a scan ID to enable exports.'}
            </p>
            {exportEnabled ? (
              <Suspense fallback={null}>
                {/* @ts-expect-error Async Server Component */}
                <FindingsExportsBoundary scanId={query.scanId} />
              </Suspense>
            ) : null}
          </div>
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
        <FindingsFilters searchParams={filterParams} />
        {hasFilters ? (
          <div className="card border-surface-muted/60 bg-surface-muted/20 px-4 py-3 text-xs text-gray-300">
            <p className="font-semibold uppercase tracking-wide text-gray-400">Active Filters</p>
            <ul className="mt-1 flex flex-wrap gap-2 font-mono">
              {filterParams.scan && <li>scan_id={filterParams.scan}</li>}
              {filterParams.severity && <li>severity={filterParams.severity}</li>}
              {filterParams.status && <li>status={filterParams.status}</li>}
              {filterParams.scope && <li>scope={filterParams.scope}</li>}
              {filterParams.tag && <li>tag={filterParams.tag}</li>}
              {filterParams.assigned && <li>assigned={filterParams.assigned}</li>}
              {filterParams.from && <li>from={filterParams.from}</li>}
              {filterParams.to && <li>to={filterParams.to}</li>}
            </ul>
          </div>
        ) : null}
      </header>
      <Suspense fallback={<FindingsTableSkeleton />}>
        {/* @ts-expect-error Async Server Component */}
        <FindingsTableBoundary query={query} searchParams={searchParams} />
      </Suspense>
      <Suspense fallback={<FindingsTimelineSkeleton />}>
        {/* @ts-expect-error Async Server Component */}
        <FindingsTimelineBoundary query={timelineQuery} />
      </Suspense>
    </section>
  );
}
