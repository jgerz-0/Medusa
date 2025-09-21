import type { Metadata } from 'next';
import { fetchScans, fetchTargets } from '@/lib/api';
import { ScansTable } from '@/components/ScansTable';
import { ScanLaunchForm } from '@/components/ScanLaunchForm';
import { RequiredRolesNotice } from '@/components/RequiredRolesNotice';
import {
  ROLE_SCAN_ENQUEUE,
  ROLE_SCANS_READ,
  ROLE_TARGETS_READ
} from '@/lib/rbac';
import type { Target } from '@/lib/types';
import type { SearchParamsInput } from '@/lib/searchParams';

export const metadata: Metadata = {
  title: 'Scans | Medusa Operations Console'
};

interface ScansPageProps {
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

export default async function ScansPage({ searchParams }: ScansPageProps) {
  let error: string | null = null;
  let scansResponse: Awaited<ReturnType<typeof fetchScans>> | null = null;
  let targets: Target[] = [];
  let targetError: string | null = null;

  const page = parsePositiveInteger(searchParams?.page, 1);
  const pageSize = parsePositiveInteger(searchParams?.page_size, 25);

  try {
    scansResponse = await fetchScans({ page, pageSize });
  } catch (err) {
    error = err instanceof Error ? err.message : 'Failed to load scans.';
  }

  try {
    targets = await fetchTargets();
  } catch (err) {
    targetError = err instanceof Error ? err.message : 'Failed to load targets.';
  }

  return (
    <section className="space-y-4">
      <header className="flex flex-col gap-2">
        <div>
          <h2 className="text-2xl font-semibold text-white">Controller Scans</h2>
          <p className="text-sm text-gray-400">
            Live view of queued, running, and completed scans pulled securely from the controller API.
          </p>
          <p className="text-xs text-gray-500">
            Launch new jobs with enforced presets to maintain deterministic, auditable coverage.
          </p>
        </div>
        <RequiredRolesNotice
          sections={[
            {
              title: 'View scan inventory',
              description: 'Lists queued, running, and completed jobs for authorized scopes.',
              roles: [ROLE_SCANS_READ]
            },
            {
              title: 'Load target catalog',
              description: 'Populates the launch form with registered, in-scope assets.',
              roles: [ROLE_TARGETS_READ]
            },
            {
              title: 'Launch scans',
              description: 'Allows dispatching nuclei, ZAP, or SQLMap jobs to workers.',
              roles: [ROLE_SCAN_ENQUEUE]
            }
          ]}
        />
      </header>
      {targetError ? (
        <div className="card border-red-500/40 bg-red-950/40 p-4 text-sm text-red-200">
          {targetError}
        </div>
      ) : (
        <ScanLaunchForm targets={targets} />
      )}
      {error ? (
        <div className="card border-red-500/40 bg-red-950/40 p-4 text-sm text-red-200">
          {error}
        </div>
      ) : (
        <ScansTable
          scans={scansResponse?.data ?? []}
          pagination={scansResponse?.pagination ?? undefined}
          searchParams={searchParams}
        />
      )}
    </section>
  );
}
