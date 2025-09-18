import Link from 'next/link';
import { formatDistanceToNow } from 'date-fns';
import { DataTable } from './DataTable';
import { StatusBadge } from './StatusBadge';
import type { Scan } from '@/lib/types';

function relativeTime(value: string) {
  return formatDistanceToNow(new Date(value), { addSuffix: true });
}

export function ScansTable({ scans }: { scans: Scan[] }) {
  return (
    <DataTable<Scan>
      itemKey={(scan) => scan.id}
      data={scans}
      emptyState={<p>No scans have been orchestrated yet.</p>}
      columns={[
        {
          key: 'target',
          header: 'Target',
          render: (scan) => (
            <Link href={`/findings?scan=${scan.id}`} className="font-semibold text-white">
              {scan.target}
            </Link>
          )
        },
        {
          key: 'status',
          header: 'Status',
          render: (scan) => <StatusBadge value={scan.status} />
        },
        {
          key: 'findings_count',
          header: 'Findings',
          render: (scan) => (
            <span className="font-mono text-sm text-gray-300">{scan.findings_count}</span>
          )
        },
        {
          key: 'created_at',
          header: 'Created',
          render: (scan) => (
            <span className="text-xs text-gray-400" title={scan.created_at}>
              {relativeTime(scan.created_at)}
            </span>
          )
        },
        {
          key: 'updated_at',
          header: 'Last Updated',
          render: (scan) => (
            <span className="text-xs text-gray-400" title={scan.updated_at}>
              {relativeTime(scan.updated_at)}
            </span>
          )
        }
      ]}
    />
  );
}
