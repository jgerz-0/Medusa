import { FindingsTable } from '@/components/FindingsTable';
import { Skeleton } from '@/components/Skeleton';
import { RequiredRolesNotice } from '@/components/RequiredRolesNotice';
import { ROLE_ANALYST, ROLE_FINDINGS_READ } from '@/lib/rbac';

export function FindingsFiltersSkeleton({ label }: { label: string }) {
  return (
    <div
      className="card border-surface-muted/60 bg-surface-muted/10 px-4 py-3"
      role="status"
      aria-live="polite"
      aria-busy="true"
      aria-label={label}
    >
      <span className="sr-only">{label}</span>
      <div className="flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
        <div className="grid flex-1 grid-cols-1 gap-3 md:grid-cols-6">
          {Array.from({ length: 5 }).map((_, index) => (
            <div key={index} className="flex flex-col gap-2">
              <Skeleton className="h-3 w-24" data-testid="table-skeleton-line" />
              <Skeleton className="h-10 w-full" data-testid="table-skeleton-line" />
            </div>
          ))}
          <div className="grid grid-cols-2 gap-2">
            <div className="flex flex-col gap-2">
              <Skeleton className="h-3 w-16" data-testid="table-skeleton-line" />
              <Skeleton className="h-10 w-full" data-testid="table-skeleton-line" />
            </div>
            <div className="flex flex-col gap-2">
              <Skeleton className="h-3 w-16" data-testid="table-skeleton-line" />
              <Skeleton className="h-10 w-full" data-testid="table-skeleton-line" />
            </div>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <Skeleton className="h-10 w-28" data-testid="table-skeleton-line" />
          <Skeleton className="h-10 w-24" data-testid="table-skeleton-line" />
        </div>
      </div>
    </div>
  );
}

export function FindingsTableSkeleton() {
  return (
    <div
      role="status"
      aria-live="polite"
      aria-busy="true"
      aria-label="Loading findings table"
      className="space-y-3"
    >
      <span className="sr-only">Loading findings table</span>
      <FindingsTable findings={[]} isLoading skeletonRowCount={6} showPaginationSkeleton />
    </div>
  );
}

export function FindingsTimelineSkeleton() {
  return (
    <div
      className="card border-surface-muted/60 bg-surface-muted/10 p-6"
      role="status"
      aria-live="polite"
      aria-busy="true"
      aria-label="Loading findings timeline"
    >
      <span className="sr-only">Loading findings timeline</span>
      <div className="space-y-4">
        <Skeleton className="h-4 w-32" data-testid="table-skeleton-line" />
        <Skeleton className="h-64 w-full" data-testid="table-skeleton-line" />
      </div>
    </div>
  );
}

export default function FindingsLoading() {
  return (
    <section className="space-y-4" aria-busy="true" aria-live="polite">
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
        <FindingsFiltersSkeleton label="Loading findings filters" />
      </header>
      <FindingsTableSkeleton />
      <FindingsTimelineSkeleton />
    </section>
  );
}
