import Link from 'next/link';
import { formatDistanceToNow } from 'date-fns';
import { DataTable, type DataTablePaginationConfig } from './DataTable';
import { StatusBadge } from './StatusBadge';
import type { Finding } from '@/lib/types';
import { buildSearchParamsHref, type SearchParamsInput } from '@/lib/searchParams';
import { ROLE_FINDINGS_READ } from '@/lib/rbac';
import type { RoleRequirement } from './RequiredRolesNotice';

function relativeTime(value: string) {
  return formatDistanceToNow(new Date(value), { addSuffix: true });
}

function scannerLabel(finding: Finding) {
  const rawScanner = finding.metadata?.['scanner'] as unknown;
  return typeof rawScanner === 'string' && rawScanner.trim() ? rawScanner : 'unknown';
}

interface FindingsTableProps {
  findings: Finding[];
  pagination?: Pick<DataTablePaginationConfig, 'page' | 'pageSize' | 'total'>;
  searchParams?: SearchParamsInput;
  basePath?: string;
  isLoading?: boolean;
  skeletonRowCount?: number;
  showPaginationSkeleton?: boolean;
}

const FINDINGS_TABLE_RBAC: RoleRequirement[] = [
  {
    title: 'View findings',
    roles: [ROLE_FINDINGS_READ]
  }
];

function buildPaginationConfig(
  pagination: Pick<DataTablePaginationConfig, 'page' | 'pageSize' | 'total'>,
  searchParams: SearchParamsInput,
  basePath: string
): DataTablePaginationConfig {
  const safePageSize = pagination.pageSize > 0 ? Math.trunc(pagination.pageSize) : 1;

  // Maintain filter scoping across pagination operations.
  return {
    ...pagination,
    pageSize: safePageSize,
    pageSizeOptions: [25, 50, 100, 200],
    onPageChange: (page) => {
      if (!Number.isFinite(page) || page < 1) {
        return undefined;
      }

      return buildSearchParamsHref({
        basePath,
        params: searchParams,
        updates: {
          page: `${Math.trunc(page)}`,
          page_size: `${safePageSize}`
        }
      });
    },
    onPageSizeChange: (pageSize) => {
      if (!Number.isFinite(pageSize) || pageSize < 1) {
        return undefined;
      }

      const normalized = Math.trunc(pageSize);
      return buildSearchParamsHref({
        basePath,
        params: searchParams,
        updates: {
          page: '1',
          page_size: `${normalized}`
        }
      });
    }
  } satisfies DataTablePaginationConfig;
}

export function FindingsTable({
  findings,
  pagination,
  searchParams,
  basePath = '/findings',
  isLoading = false,
  skeletonRowCount,
  showPaginationSkeleton
}: FindingsTableProps) {
  const tablePagination = pagination ? buildPaginationConfig(pagination, searchParams, basePath) : undefined;

  return (
    <DataTable<Finding>
      caption="Findings"
      ariaLabel="Findings"
      itemKey={(finding) => finding.id}
      data={findings}
      emptyState={<p>No findings were produced for this selection.</p>}
      pagination={tablePagination}
      isLoading={isLoading}
      skeletonRowCount={skeletonRowCount}
      showPaginationSkeleton={showPaginationSkeleton}
      requiredRoleSections={FINDINGS_TABLE_RBAC}
      columns={[
        {
          key: 'title',
          header: 'Finding',
          skeletonClassName: 'w-3/4',
          skeletonLines: 3,
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
              <span className="text-xs text-gray-500">
                {finding.assigned_to ? `Assigned to ${finding.assigned_to}` : 'Unassigned'} • {finding.comment_count} comment
                {finding.comment_count === 1 ? '' : 's'}
              </span>
            </div>
          )
        },
        {
          key: 'severity',
          header: 'Severity',
          skeletonClassName: 'w-20',
          skeletonLines: 1,
          render: (finding) => <StatusBadge value={finding.severity} />
        },
        {
          key: 'status',
          header: 'Status',
          skeletonClassName: 'w-20',
          skeletonLines: 1,
          render: (finding) => <StatusBadge value={finding.status} />
        },
        {
          key: 'tags',
          header: 'Tags',
          skeletonClassName: 'w-32',
          skeletonLines: 2,
          render: (finding) => (
            <div className="flex flex-wrap gap-1 text-xs text-gray-300">
              {finding.tags.length > 0 ? (
                finding.tags.map((tag) => (
                  <span
                    key={tag}
                    className="rounded-full bg-surface-muted/40 px-2 py-0.5 text-[10px] uppercase tracking-wide text-gray-300"
                  >
                    {tag}
                  </span>
                ))
              ) : (
                <span className="text-gray-500">none</span>
              )}
            </div>
          )
        },
        {
          key: 'enrichment',
          header: 'Enrichment',
          skeletonClassName: 'w-28',
          skeletonLines: 2,
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
          skeletonClassName: 'w-32',
          skeletonLines: 1,
          render: (finding) => (
            <span className="text-xs text-gray-400" title={finding.detected_at}>
              {relativeTime(finding.detected_at)}
            </span>
          )
        },
        {
          key: 'updated_at',
          header: 'Last Updated',
          skeletonClassName: 'w-32',
          skeletonLines: 1,
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
