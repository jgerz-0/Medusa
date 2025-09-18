import type { Metadata } from 'next';
import { fetchFindings } from '@/lib/api';
import type { Finding } from '@/lib/types';
import { FindingsTable } from '@/components/FindingsTable';

export const metadata: Metadata = {
  title: 'Findings | Medusa Operations Console'
};

interface FindingsPageProps {
  searchParams?: {
    scan?: string;
    severity?: string;
    status?: string;
  };
}

function filterFindings(findings: Finding[], searchParams?: FindingsPageProps['searchParams']) {
  if (!searchParams) {
    return findings;
  }

  return findings.filter((finding) => {
    if (searchParams.scan && finding.scan_id !== searchParams.scan) {
      return false;
    }

    if (searchParams.severity && finding.severity !== searchParams.severity) {
      return false;
    }

    if (searchParams.status && finding.status !== searchParams.status) {
      return false;
    }

    return true;
  });
}

export default async function FindingsPage({ searchParams }: FindingsPageProps) {
  let error: string | null = null;
  let findings: Finding[] = [];

  try {
    const data = await fetchFindings();
    findings = filterFindings(data, searchParams);
  } catch (err) {
    error = err instanceof Error ? err.message : 'Failed to load findings.';
  }

  const hasFilters = Boolean(
    searchParams?.scan || searchParams?.severity || searchParams?.status
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
        {hasFilters ? (
          <div className="card border-surface-muted/60 bg-surface-muted/20 px-4 py-3 text-xs text-gray-300">
            <p className="font-semibold uppercase tracking-wide text-gray-400">Active Filters</p>
            <ul className="mt-1 flex flex-wrap gap-2 font-mono">
              {searchParams?.scan && <li>scan_id={searchParams.scan}</li>}
              {searchParams?.severity && <li>severity={searchParams.severity}</li>}
              {searchParams?.status && <li>status={searchParams.status}</li>}
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
    </section>
  );
}
