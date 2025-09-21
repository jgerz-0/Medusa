import clsx from 'clsx';
import { Skeleton } from './Skeleton';

interface TableSkeletonColumn {
  key: string;
  header: string;
  widthClass?: string;
  lineWidths?: string[];
}

interface TableSkeletonProps {
  caption: string;
  columns: TableSkeletonColumn[];
  rowCount?: number;
  loadingLabel?: string;
  showPagination?: boolean;
}

export function TableSkeleton({
  caption,
  columns,
  rowCount = 6,
  loadingLabel,
  showPagination = true
}: TableSkeletonProps) {
  const rows = Array.from({ length: Math.max(1, rowCount) });
  const statusLabel = loadingLabel ?? `Loading ${caption}`;

  return (
    <div
      className="space-y-3"
      role="status"
      aria-live="polite"
      aria-busy="true"
      aria-label={statusLabel}
      data-testid="table-skeleton"
    >
      <span className="sr-only">{statusLabel}</span>
      <div className="card overflow-hidden">
        <table className="table-grid">
          <caption className="sr-only">{caption}</caption>
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
          <tbody className="divide-y divide-surface-muted/70">
            {rows.map((_, rowIndex) => (
              <tr key={rowIndex}>
                {columns.map((column) => {
                  const lineWidths = column.lineWidths?.length
                    ? column.lineWidths
                    : [column.widthClass ?? 'w-full'];

                  return (
                    <td key={column.key} className="px-4 py-3">
                      <div className="flex flex-col gap-2">
                        {lineWidths.map((lineWidth, lineIndex) => (
                          <Skeleton
                            key={`${column.key}-${lineIndex}`}
                            className={clsx(lineIndex === 0 ? 'h-4' : 'h-3', lineWidth)}
                            data-testid="table-skeleton-line"
                          />
                        ))}
                      </div>
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {showPagination ? (
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
