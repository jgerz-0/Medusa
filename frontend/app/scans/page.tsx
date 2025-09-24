import { Suspense } from 'react';
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
import type { SearchParamsInput } from '@/lib/searchParams';
import { ScanLaunchFormSkeleton, ScansTableSkeleton } from './loading';

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

async function ScanLaunchFormBoundary() {
  try {
    const targets = await fetchTargets();
    return <ScanLaunchForm targets={targets} />;
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Failed to load targets.';
    return (
      <div className="card border-red-500/40 bg-red-950/40 p-4 text-sm text-red-200" role="alert">
        {message}
      </div>
    );
  }
}

interface ScansTableBoundaryProps {
  page: number;
  pageSize: number;
  searchParams?: SearchParamsInput;
}

async function ScansTableBoundary(props?: ScansTableBoundaryProps) {
  if (!props) {
    return (
      <div className="card border-red-500/40 bg-red-950/40 p-4 text-sm text-red-200" role="alert">
        Failed to load scans.
      </div>
    );
  }

  const { page, pageSize, searchParams } = props;

  try {
    const scansResponse = await fetchScans({ page, pageSize });
    return (
      <ScansTable
        scans={scansResponse.data ?? []}
        pagination={scansResponse.pagination ?? undefined}
        searchParams={searchParams}
      />
    );
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Failed to load scans.';
    return (
      <div className="card border-red-500/40 bg-red-950/40 p-4 text-sm text-red-200" role="alert">
        {message}
      </div>
    );
  }
}

export default function ScansPage({ searchParams }: ScansPageProps) {
  const page = parsePositiveInteger(searchParams?.page, 1);
  const pageSize = parsePositiveInteger(searchParams?.page_size, 25);

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
      <Suspense fallback={<ScanLaunchFormSkeleton />}>
        {/* @ts-expect-error Async Server Component */}
        <ScanLaunchFormBoundary />
      </Suspense>
      <Suspense fallback={<ScansTableSkeleton />}>
        {/* @ts-expect-error Async Server Component */}
        <ScansTableBoundary page={page} pageSize={pageSize} searchParams={searchParams} />
      </Suspense>
    </section>
  );
}
