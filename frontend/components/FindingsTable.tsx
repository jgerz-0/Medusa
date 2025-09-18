import Link from 'next/link';
import { formatDistanceToNow } from 'date-fns';
import { DataTable } from './DataTable';
import { StatusBadge } from './StatusBadge';
import type { Finding } from '@/lib/types';

function relativeTime(value: string) {
  return formatDistanceToNow(new Date(value), { addSuffix: true });
}

export function FindingsTable({ findings }: { findings: Finding[] }) {
  return (
    <DataTable<Finding>
      itemKey={(finding) => finding.id}
      data={findings}
      emptyState={<p>No findings were produced for this selection.</p>}
      columns={[
        {
          key: 'title',
          header: 'Finding',
          render: (finding) => (
            <div className="flex flex-col">
              <Link
                href={`/findings/${finding.id}`}
                className="font-semibold text-white"
                data-testid="finding-title"
              >
                {finding.title}
              </Link>
              <span className="text-xs text-gray-400">Template {finding.template_id}</span>
            </div>
          )
        },
        {
          key: 'severity',
          header: 'Severity',
          render: (finding) => <StatusBadge value={finding.severity} />
        },
        {
          key: 'status',
          header: 'Status',
          render: (finding) => <StatusBadge value={finding.status} />
        },
        {
          key: 'detected_at',
          header: 'Detected',
          render: (finding) => (
            <span className="text-xs text-gray-400" title={finding.detected_at}>
              {relativeTime(finding.detected_at)}
            </span>
          )
        },
        {
          key: 'updated_at',
          header: 'Last Updated',
          render: (finding) => (
            <span className="text-xs text-gray-400" title={finding.updated_at}>
              {relativeTime(finding.updated_at)}
            </span>
          )
        }
      ]}
    />
  );
}
