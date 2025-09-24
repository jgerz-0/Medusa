import Link from 'next/link';
import { formatDistanceToNow } from 'date-fns';
import { DataTable, type DataTablePaginationConfig } from './DataTable';
import { StatusBadge } from './StatusBadge';
import type { Scan } from '@/lib/types';
import { buildSearchParamsHref, type SearchParamsInput } from '@/lib/searchParams';
import { ROLE_SCANS_READ } from '@/lib/rbac';
import type { RoleRequirement } from './RequiredRolesNotice';

function relativeTime(value: string) {
  return formatDistanceToNow(new Date(value), { addSuffix: true });
}

interface ScansTableProps {
  scans: Scan[];
  pagination?: Pick<DataTablePaginationConfig, 'page' | 'pageSize' | 'total'>;
  searchParams?: SearchParamsInput;
  basePath?: string;
  isLoading?: boolean;
  skeletonRowCount?: number;
  showPaginationSkeleton?: boolean;
}

const SCAN_TABLE_RBAC: RoleRequirement[] = [
  {
    title: 'View scan inventory',
    roles: [ROLE_SCANS_READ]
  }
];

function buildPaginationConfig(
  pagination: Pick<DataTablePaginationConfig, 'page' | 'pageSize' | 'total'>,
  searchParams: SearchParamsInput,
  basePath: string
): DataTablePaginationConfig {
  const safePageSize = pagination.pageSize > 0 ? Math.trunc(pagination.pageSize) : 1;

  // Preserve any active filters while emitting deterministic pagination links.
  return {
    ...pagination,
    pageSize: safePageSize,
    pageSizeOptions: [10, 25, 50, 100],
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

export function ScansTable({
  scans,
  pagination,
  searchParams,
  basePath = '/scans',
  isLoading = false,
  skeletonRowCount,
  showPaginationSkeleton
}: ScansTableProps) {
  const tablePagination = pagination ? buildPaginationConfig(pagination, searchParams, basePath) : undefined;

  return (
    <DataTable<Scan>
      caption="Scans"
      ariaLabel="Scans"
      itemKey={(scan) => scan.id}
      data={scans}
      emptyState={<p>No scans have been orchestrated yet.</p>}
      pagination={tablePagination}
      isLoading={isLoading}
      skeletonRowCount={skeletonRowCount}
      showPaginationSkeleton={showPaginationSkeleton}
      requiredRoleSections={SCAN_TABLE_RBAC}
      columns={[
        {
          key: 'target',
          header: 'Target',
          skeletonClassName: 'w-48',
          skeletonLines: 1,
          render: (scan) => (
            <Link href={`/findings?scan=${scan.id}`} className="font-semibold text-white">
              {scan.target}
            </Link>
          )
        },
        {
          key: 'scanner',
          header: 'Scanner',
          skeletonClassName: 'w-24',
          skeletonLines: 1,
          render: (scan) => (
            <span className="font-mono text-xs uppercase tracking-wide text-gray-300">{scan.scanner}</span>
          )
        },
        {
          key: 'status',
          header: 'Status',
          skeletonClassName: 'w-24',
          skeletonLines: 1,
          render: (scan) => <StatusBadge value={scan.status} />
        },
        {
          key: 'findings_count',
          header: 'Findings',
          skeletonClassName: 'w-16',
          skeletonLines: 1,
          render: (scan) => (
            <span className="font-mono text-sm text-gray-300">{scan.findings_count}</span>
          )
        },
        {
          key: 'created_at',
          header: 'Created',
          skeletonClassName: 'w-28',
          skeletonLines: 1,
          render: (scan) => (
            <span className="text-xs text-gray-400" title={scan.created_at}>
              {relativeTime(scan.created_at)}
            </span>
          )
        },
        {
          key: 'updated_at',
          header: 'Last Updated',
          skeletonClassName: 'w-28',
          skeletonLines: 1,
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
