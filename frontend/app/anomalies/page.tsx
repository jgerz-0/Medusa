import type { Metadata } from 'next';
import { fetchAnomalies } from '@/lib/api';
import { AnomaliesTable } from '@/components/AnomaliesTable';
import { AnomaliesTimeline } from '@/components/AnomaliesTimeline';
import { RequiredRolesNotice } from '@/components/RequiredRolesNotice';
import { ROLE_ANALYST, ROLE_FINDINGS_READ } from '@/lib/rbac';
import type { SearchParamsInput } from '@/lib/searchParams';

export const metadata: Metadata = {
  title: 'Anomalies | Medusa Operations Console'
};

interface AnomaliesPageProps {
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

export default async function AnomaliesPage({ searchParams }: AnomaliesPageProps) {
  const page = parsePositiveInteger(searchParams?.page, 1);
  const pageSize = parsePositiveInteger(searchParams?.page_size, 25);

  const query = {
    type: typeof searchParams?.type === 'string' ? searchParams.type : undefined,
    actor: typeof searchParams?.actor === 'string' ? searchParams.actor : undefined,
    source: typeof searchParams?.source === 'string' ? searchParams.source : undefined,
    from: typeof searchParams?.from === 'string' ? searchParams.from : undefined,
    to: typeof searchParams?.to === 'string' ? searchParams.to : undefined,
    page,
    pageSize
  } as const;

  let error: string | null = null;
  let anomaliesResponse: Awaited<ReturnType<typeof fetchAnomalies>> | null = null;

  try {
    anomaliesResponse = await fetchAnomalies(query);
  } catch (err) {
    error = err instanceof Error ? err.message : 'Failed to load anomalies.';
  }

  const events = anomaliesResponse?.data ?? [];
  const pagination = anomaliesResponse?.pagination ?? null;

  const hasFilters = Boolean(query.type || query.actor || query.source || query.from || query.to);

  return (
    <section className="space-y-4">
      <header className="space-y-2">
        <div className="flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
          <div>
            <h2 className="text-2xl font-semibold text-white">Anomaly Signals</h2>
            <p className="text-sm text-gray-400">
              Controller-side anomaly callbacks highlight authentication abuse, traffic spikes, and other suspicious activity. Metadata is sanitized server-side so analysts can review safely.
            </p>
          </div>
        </div>
        <RequiredRolesNotice
          sections={[
            {
              title: 'Review anomaly events',
              description: 'Allows analysts to inspect sanitized anomaly metadata and timelines.',
              roles: [ROLE_FINDINGS_READ]
            },
            {
              title: 'Triage and escalation',
              description: 'Required to pivot from anomalies into validation workflows or deeper investigations.',
              roles: [ROLE_ANALYST]
            }
          ]}
        />
      </header>

      {error ? (
        <div className="card border border-red-500/40 bg-red-500/10 p-4 text-sm text-red-200" role="alert">
          <p className="font-semibold">Unable to load anomalies</p>
          <p className="text-xs text-red-100/80">{error}</p>
        </div>
      ) : null}

      {hasFilters ? (
        <div className="card border-surface-muted/60 bg-surface-muted/20 px-4 py-3 text-xs text-gray-300">
          <p className="font-semibold uppercase tracking-wide text-gray-400">Active Filters</p>
          <ul className="mt-1 flex flex-wrap gap-2 font-mono">
            {query.type && <li>type={query.type}</li>}
            {query.actor && <li>actor={query.actor}</li>}
            {query.source && <li>source={query.source}</li>}
            {query.from && <li>from={query.from}</li>}
            {query.to && <li>to={query.to}</li>}
          </ul>
        </div>
      ) : null}

      <AnomaliesTable
        events={events}
        pagination={pagination ?? undefined}
        searchParams={searchParams}
      />

      <AnomaliesTimeline events={events} />
    </section>
  );
}
