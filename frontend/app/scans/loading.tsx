import { TableSkeleton } from '@/components/TableSkeleton';
import { Skeleton } from '@/components/Skeleton';
import { RequiredRolesNotice } from '@/components/RequiredRolesNotice';
import {
  ROLE_SCAN_ENQUEUE,
  ROLE_SCANS_READ,
  ROLE_TARGETS_READ
} from '@/lib/rbac';

export default function ScansLoading() {
  return (
    <section className="space-y-4" aria-busy="true" aria-live="polite">
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
      <div
        className="card border-surface-muted/60 bg-surface-muted/10 p-6"
        role="status"
        aria-live="polite"
        aria-busy="true"
        aria-label="Loading scan launch form"
      >
        <span className="sr-only">Loading scan launch form</span>
        <div className="grid gap-6 md:grid-cols-2">
          <div className="space-y-4">
            <Skeleton className="h-4 w-48" data-testid="table-skeleton-line" />
            <Skeleton className="h-12 w-full" data-testid="table-skeleton-line" />
            <Skeleton className="h-24 w-full" data-testid="table-skeleton-line" />
          </div>
          <div className="space-y-4">
            <Skeleton className="h-4 w-40" data-testid="table-skeleton-line" />
            <Skeleton className="h-10 w-full" data-testid="table-skeleton-line" />
            <Skeleton className="h-20 w-full" data-testid="table-skeleton-line" />
          </div>
        </div>
        <div className="mt-6 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
          <Skeleton className="h-10 w-48 md:w-64" data-testid="table-skeleton-line" />
          <div className="flex flex-wrap gap-3">
            {Array.from({ length: 3 }).map((_, index) => (
              <Skeleton key={index} className="h-10 w-32" data-testid="table-skeleton-line" />
            ))}
          </div>
        </div>
      </div>
      <TableSkeleton
        caption="Scans"
        loadingLabel="Loading scans table"
        columns={[
          { key: 'target', header: 'Target', widthClass: 'w-48' },
          { key: 'scanner', header: 'Scanner', widthClass: 'w-24' },
          { key: 'status', header: 'Status', widthClass: 'w-24' },
          { key: 'findings', header: 'Findings', widthClass: 'w-16' },
          { key: 'created', header: 'Created', widthClass: 'w-28' },
          { key: 'updated', header: 'Last Updated', widthClass: 'w-28' }
        ]}
      />
    </section>
  );
}
