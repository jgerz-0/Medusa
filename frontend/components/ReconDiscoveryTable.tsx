'use client';

import clsx from 'clsx';
import { formatDistanceToNow } from 'date-fns';
import { DataTable } from './DataTable';
import type { ReconDiscovery } from '@/lib/types';

interface ReconDiscoveryTableProps {
  discoveries: ReconDiscovery[];
  selectedDiscoveryId?: string | null;
  onSelect?: (discoveryId: string) => void;
}

const diffStatusStyles: Record<
  ReconDiscovery['diff_status'],
  { label: string; className: string; description: string }
> = {
  approved: {
    label: 'Approved',
    className: 'bg-emerald-500/10 text-emerald-300 border border-emerald-500/30',
    description: 'Discovery already promoted into the authorized target registry.'
  },
  in_scope: {
    label: 'Matches Scope',
    className: 'bg-sky-500/10 text-sky-300 border border-sky-500/30',
    description: 'Asset sits inside an existing target scope; no action required.'
  },
  scope_extension: {
    label: 'Scope Extension',
    className: 'bg-amber-500/10 text-amber-200 border border-amber-500/30',
    description: 'Asset expands the authorized boundary. Review and promote if approved by client.'
  },
  unmatched: {
    label: 'Out of Scope',
    className: 'bg-rose-500/10 text-rose-200 border border-rose-500/30',
    description: 'Recon found an asset outside current scope. Confirm authorization before promotion.'
  }
};

function relativeTime(value: string): string {
  return formatDistanceToNow(new Date(value), { addSuffix: true });
}

export function ReconDiscoveryTable({
  discoveries,
  selectedDiscoveryId,
  onSelect
}: ReconDiscoveryTableProps) {
  return (
    <div className="space-y-3">
      <header className="space-y-1">
        <h3 className="text-lg font-semibold text-white">Recon Discoveries</h3>
        <p className="text-sm text-gray-400">
          Each row reflects the normalized asset emitted by the recon worker. Diff status highlights how the discovery
          aligns with the currently authorized scope.
        </p>
      </header>

      <DataTable<ReconDiscovery>
        data={discoveries}
        itemKey={(discovery) => discovery.id}
        emptyState={<p>No recon discoveries have been recorded yet.</p>}
        columns={[
          {
            key: 'asset',
            header: 'Asset',
            render: (discovery) => (
              <div className="space-y-1">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <p className="font-semibold text-white">{discovery.value}</p>
                    <p className="text-xs text-gray-400 uppercase tracking-wide">{discovery.asset_type}</p>
                  </div>
                  <span className="rounded-full border border-surface-muted/60 bg-surface-muted/40 px-2 py-1 text-xs text-gray-300">
                    {discovery.source}
                  </span>
                </div>
                {discovery.raw_value && discovery.raw_value !== discovery.value ? (
                  <p className="text-xs text-gray-500" title={discovery.raw_value}>
                    Raw: {discovery.raw_value}
                  </p>
                ) : null}
                <p className="text-xs font-mono text-gray-500">ID: {discovery.id}</p>
              </div>
            )
          },
          {
            key: 'diff',
            header: 'Diff Status',
            render: (discovery) => {
              const descriptor = diffStatusStyles[discovery.diff_status];
              return (
                <div className="space-y-1">
                  <span
                    className={clsx(
                      'inline-flex w-fit items-center gap-2 rounded-full px-3 py-1 text-xs font-medium',
                      descriptor.className
                    )}
                  >
                    {descriptor.label}
                  </span>
                  <p className="text-[11px] text-gray-500">{descriptor.description}</p>
                </div>
              );
            }
          },
          {
            key: 'scope',
            header: 'Matched Scope',
            render: (discovery) => (
              <div className="text-xs text-gray-300">
                {discovery.matched_scope ? (
                  <span className="font-mono" title={discovery.matched_scope}>
                    {discovery.matched_scope}
                  </span>
                ) : (
                  <span className="text-gray-500">Unmatched</span>
                )}
              </div>
            )
          },
          {
            key: 'status',
            header: 'Status',
            render: (discovery) => (
              <span
                className={clsx(
                  'inline-flex items-center rounded-full px-2 py-1 text-xs font-medium uppercase tracking-wide',
                  discovery.status === 'approved'
                    ? 'bg-emerald-500/10 text-emerald-300'
                    : 'bg-surface-muted/60 text-gray-300'
                )}
              >
                {discovery.status}
              </span>
            )
          },
          {
            key: 'observed',
            header: 'Observed',
            render: (discovery) => (
              <div className="text-xs text-gray-400">
                <p title={discovery.first_seen}>First: {relativeTime(discovery.first_seen)}</p>
                <p title={discovery.last_seen}>Last: {relativeTime(discovery.last_seen)}</p>
                <p className="text-[11px] text-gray-500">Occurrences: {discovery.occurrences}</p>
              </div>
            )
          },
          {
            key: 'actions',
            header: 'Promote',
            className: 'w-32',
            render: (discovery) => {
              const isSelected = discovery.id === selectedDiscoveryId;
              return (
                <button
                  type="button"
                  onClick={() => onSelect?.(discovery.id)}
                  className={clsx(
                    'w-full rounded-md border px-3 py-2 text-xs font-semibold transition',
                    isSelected
                      ? 'border-emerald-500/60 bg-emerald-500/20 text-emerald-100'
                      : 'border-surface-muted/60 bg-surface-muted/30 text-gray-200 hover:border-emerald-500/60 hover:text-emerald-200'
                  )}
                  aria-pressed={isSelected}
                >
                  {isSelected ? 'Selected' : 'Review'}
                </button>
              );
            }
          }
        ]}
      />
    </div>
  );
}
