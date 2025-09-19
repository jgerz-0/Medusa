import Link from 'next/link';
import { formatDistanceToNow } from 'date-fns';
import { DataTable } from './DataTable';
import { StatusBadge } from './StatusBadge';
import type { Finding } from '@/lib/types';

function relativeTime(value: string) {
  return formatDistanceToNow(new Date(value), { addSuffix: true });
}

function scannerLabel(finding: Finding) {
  const rawScanner = finding.metadata?.['scanner'] as unknown;
  return typeof rawScanner === 'string' && rawScanner.trim() ? rawScanner : 'unknown';
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
              <span className="text-xs text-gray-400">
                Scanner {scannerLabel(finding)} • Rule {finding.template_id}
              </span>
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
          key: 'enrichment',
          header: 'Enrichment',
          render: (finding) => {
            const latest = finding.enrichments?.[0];
            if (!latest) {
              return <span className="text-xs text-gray-500">Not enriched</span>;
            }
            const advisoryCount = latest.advisories?.length ?? 0;
            const errorCount = Object.keys(latest.errors ?? {}).length;
            const enrichmentSummary =
              advisoryCount > 0
                ? `${advisoryCount} advisory${advisoryCount === 1 ? '' : 'ies'}`
                : errorCount > 0
                  ? `${errorCount} error${errorCount === 1 ? '' : 's'}`
                  : 'No advisories';
            const timestamp = latest.generated_at ?? latest.recorded_at;
            return (
              <div className="flex flex-col">
                <span
                  className={`text-xs ${errorCount > 0 ? 'text-red-400' : 'text-gray-200'}`}
                >
                  {enrichmentSummary}
                </span>
                {timestamp ? (
                  <span className="text-xs text-gray-500" title={timestamp}>
                    {relativeTime(timestamp)}
                  </span>
                ) : null}
              </div>
            );
          }
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
