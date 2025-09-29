import Link from 'next/link';
import clsx from 'clsx';
import { ReactNode } from 'react';
import { Skeleton } from './Skeleton';
import { InlineRoleBadges, type RoleRequirement } from './RequiredRolesNotice';

interface Column<T> {
  key: string;
  header: string;
  className?: string;
  render?: (item: T) => ReactNode;
  skeletonClassName?: string;
  skeletonLines?: number;
}

export interface DataTablePaginationConfig {
  page: number;
  pageSize: number;
  total: number;
  pageSizeOptions?: number[];
  onPageChange?: (page: number) => string | undefined;
  onPageSizeChange?: (pageSize: number) => string | undefined;
}

interface DataTableProps<T> {
  columns: Column<T>[];
  data: T[];
  emptyState?: ReactNode;
  itemKey: (item: T) => string;
  pagination?: DataTablePaginationConfig;
  caption?: string;
  ariaLabel?: string;
  isLoading?: boolean;
  skeletonRowCount?: number;
  requiredRoleSections?: RoleRequirement[];
  requiredRoleLabel?: string;
  showPaginationSkeleton?: boolean;
}

interface PaginationLinkProps {
  label: string;
  href?: string;
  disabled?: boolean;
}

function PaginationLink({ label, href, disabled }: PaginationLinkProps) {
  const baseClasses =
    'inline-flex items-center justify-center rounded border px-3 py-1 text-xs font-semibold uppercase tracking-wide transition';

  if (!href || disabled) {
    return (
      <span
        aria-disabled="true"
        className={`${baseClasses} cursor-not-allowed border-surface-muted/30 bg-surface-muted/30 text-gray-500`}
      >
        {label}
      </span>
    );
  }

  return (
    <Link
      href={href}
      className={`${baseClasses} border-surface-muted/60 text-gray-200 hover:bg-surface-muted/50 hover:text-white`}
      prefetch={false}
    >
      {label}
    </Link>
  );
}

function safeInvoke(handler: ((value: number) => string | undefined) | undefined, value: number) {
  if (!handler) {
    return undefined;
  }
  if (!Number.isFinite(value) || value < 1) {
    return undefined;
  }

  try {
    const href = handler(value);
    return typeof href === 'string' && href.trim().length > 0 ? href : undefined;
  } catch (error) {
    // Defensive: avoid leaking errors from link builders into render flow.
    return undefined;
  }
}

export function DataTablePager({ pagination }: { pagination: DataTablePaginationConfig }) {
  // Render navigation purely with server-computed links to keep pagination deterministic and auditable.
  const safePageSize =
    Number.isFinite(pagination.pageSize) && pagination.pageSize > 0
      ? Math.trunc(pagination.pageSize)
      : 1;
  const safeTotal = Number.isFinite(pagination.total) && pagination.total > 0 ? Math.trunc(pagination.total) : 0;
  const totalPages = safePageSize > 0 ? Math.max(1, Math.ceil(safeTotal / safePageSize)) : 1;
  const rawPage = Number.isFinite(pagination.page) && pagination.page > 0 ? Math.trunc(pagination.page) : 1;
  const currentPage = Math.min(Math.max(rawPage, 1), totalPages);
  const rangeStart = safeTotal === 0 ? 0 : (currentPage - 1) * safePageSize + 1;
  const rangeEnd = safeTotal === 0 ? 0 : Math.min(safeTotal, currentPage * safePageSize);

  const sizeOptions = Array.from(
    new Set([...(pagination.pageSizeOptions ?? []), safePageSize].filter((value) => Number.isFinite(value) && value > 0))
  ).sort((a, b) => a - b);

  const firstHref = currentPage > 1 ? safeInvoke(pagination.onPageChange, 1) : undefined;
  const previousHref = currentPage > 1 ? safeInvoke(pagination.onPageChange, currentPage - 1) : undefined;
  const nextHref = currentPage < totalPages ? safeInvoke(pagination.onPageChange, currentPage + 1) : undefined;
  const lastHref = currentPage < totalPages ? safeInvoke(pagination.onPageChange, totalPages) : undefined;

  return (
    <div className="flex flex-col gap-3 rounded-md border border-surface-muted/60 bg-surface-muted/20 px-4 py-3 text-xs text-gray-400 md:flex-row md:items-center md:justify-between">
      <div role="status" aria-live="polite" aria-atomic="true">
        <p className="font-medium text-gray-300">
          Showing{' '}
          <span className="text-white">
            {rangeStart.toLocaleString()}–{rangeEnd.toLocaleString()}
          </span>{' '}
          of <span className="text-white">{safeTotal.toLocaleString()}</span>
        </p>
        <p className="text-[11px] uppercase tracking-wide text-gray-500">
          Page {currentPage.toLocaleString()} of {totalPages.toLocaleString()} • {safePageSize.toLocaleString()} rows per page
        </p>
      </div>
      <div className="flex flex-col gap-2 md:flex-row md:items-center md:gap-4" aria-label="Pagination controls">
        <div className="flex items-center gap-1 text-[11px] uppercase tracking-wide text-gray-500">
          <span>Rows:</span>
          <div className="flex gap-1">
            {sizeOptions.map((size) => {
              const isActive = size === safePageSize;
              const href = isActive ? undefined : safeInvoke(pagination.onPageSizeChange, size);

              if (!href) {
                return (
                  <span
                    key={size}
                    className={`inline-flex items-center rounded border px-2 py-0.5 text-[11px] font-semibold ${
                      isActive
                        ? 'border-surface-muted/40 bg-surface-muted/50 text-white'
                        : 'border-surface-muted/30 text-gray-500'
                    }`}
                    aria-current={isActive ? 'page' : undefined}
                  >
                    {size}
                  </span>
                );
              }

              return (
                <Link
                  key={size}
                  href={href}
                  className="inline-flex items-center rounded border border-surface-muted/60 px-2 py-0.5 text-[11px] font-semibold text-gray-200 transition hover:bg-surface-muted/50 hover:text-white"
                  prefetch={false}
                >
                  {size}
                </Link>
              );
            })}
          </div>
        </div>
        <div className="flex items-center gap-1">
          <PaginationLink label="First" href={firstHref} disabled={!firstHref} />
          <PaginationLink label="Prev" href={previousHref} disabled={!previousHref} />
          <PaginationLink label="Next" href={nextHref} disabled={!nextHref} />
          <PaginationLink label="Last" href={lastHref} disabled={!lastHref} />
        </div>
      </div>
    </div>
  );
}

function renderSkeletonCell(lines: number, className?: string) {
  const safeLines = Number.isFinite(lines) && lines > 0 ? Math.trunc(lines) : 1;
  return (
    <div className="flex flex-col gap-2">
      {Array.from({ length: safeLines }).map((_, index) => (
        <Skeleton
          key={index}
          className={clsx(index === 0 ? 'h-4' : 'h-3', className ?? 'w-full')}
          data-testid="table-skeleton-line"
        />
      ))}
    </div>
  );
}

export function DataTable<T>({
  columns,
  data,
  emptyState,
  itemKey,
  pagination,
  caption,
  ariaLabel,
  isLoading = false,
  skeletonRowCount = 6,
  requiredRoleSections,
  requiredRoleLabel = 'Controller RBAC',
  showPaginationSkeleton = true
}: DataTableProps<T>) {
  const hasRows = data.length > 0;
  const showSkeleton = isLoading;
  const shouldRenderEmptyState = !showSkeleton && !hasRows;
  const tableCaption = caption ?? ariaLabel;
  const tableLabel = ariaLabel ?? caption;
  const skeletonRows = Array.from({ length: Math.max(1, Math.trunc(skeletonRowCount)) });
  const renderRoleBadges =
    requiredRoleSections && requiredRoleSections.length > 0 ? (
      <InlineRoleBadges sections={requiredRoleSections} label={requiredRoleLabel} />
    ) : null;

  return (
    <div className="space-y-3">
      {renderRoleBadges}
      {showSkeleton || hasRows ? (
        <div className="card overflow-hidden" aria-live={showSkeleton ? 'polite' : undefined}>
          <table className="table-grid" aria-label={tableLabel} aria-busy={showSkeleton || undefined}>
            {tableCaption ? <caption className="sr-only">{tableCaption}</caption> : null}
            <thead className="bg-surface-muted/60">
              <tr>
                {columns.map((column) => (
                  <th
                    key={column.key}
                    scope="col"
                    className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide text-gray-400"
                  >
                    {column.header}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-muted/70" aria-hidden={showSkeleton || undefined}>
              {showSkeleton
                ? skeletonRows.map((_, rowIndex) => (
                    <tr key={`skeleton-${rowIndex}`} className="hover:bg-surface-muted/40">
                      {columns.map((column) => (
                        <td key={column.key} className={`px-4 py-3 ${column.className ?? ''}`}>
                          {renderSkeletonCell(column.skeletonLines ?? 1, column.skeletonClassName)}
                        </td>
                      ))}
                    </tr>
                  ))
                : data.map((item) => (
                    <tr key={itemKey(item)} className="hover:bg-surface-muted/40">
                      {columns.map((column) => (
                        <td key={column.key} className={`px-4 py-3 text-sm text-gray-200 ${column.className ?? ''}`}>
                          {column.render ? column.render(item) : (item as Record<string, ReactNode>)[column.key]}
                        </td>
                      ))}
                    </tr>
                  ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="card p-6 text-center text-sm text-gray-400">
          {emptyState ?? 'No records to display yet.'}
        </div>
      )}

      {pagination && !showSkeleton ? <DataTablePager pagination={pagination} /> : null}
      {showSkeleton && showPaginationSkeleton ? (
        <div className="card border-surface-muted/60 bg-surface-muted/20 px-4 py-3">
          <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
            <div className="space-y-2">
              <Skeleton className="h-4 w-40" data-testid="table-skeleton-line" />
              <Skeleton className="h-3 w-32" data-testid="table-skeleton-line" />
            </div>
            <div className="flex flex-col gap-2 md:flex-row md:items-center md:gap-4">
              <Skeleton className="h-8 w-28 md:w-32" data-testid="table-skeleton-line" />
              <div className="flex gap-2">
                {Array.from({ length: 4 }).map((_, index) => (
                  <Skeleton key={index} className="h-8 w-16" data-testid="table-skeleton-line" />
                ))}
              </div>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}
