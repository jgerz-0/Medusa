import { formatDistanceToNow } from 'date-fns';
import { DataTable, type DataTablePaginationConfig } from './DataTable';
import type { AnomalyEvent } from '@/lib/types';
import { buildSearchParamsHref, type SearchParamsInput } from '@/lib/searchParams';

function relativeTime(value: string) {
  return formatDistanceToNow(new Date(value), { addSuffix: true });
}

function metadataPreview(metadata: Record<string, unknown>): string {
  try {
    const serialized = JSON.stringify(metadata ?? {}, null, 2);
    if (serialized.length > 280) {
      return `${serialized.slice(0, 280)}…`;
    }
    return serialized;
  } catch (error) {
    return 'Unavailable';
  }
}

interface AnomaliesTableProps {
  events: AnomalyEvent[];
  pagination?: Pick<DataTablePaginationConfig, 'page' | 'pageSize' | 'total'>;
  searchParams?: SearchParamsInput;
  basePath?: string;
}

function buildPaginationConfig(
  pagination: Pick<DataTablePaginationConfig, 'page' | 'pageSize' | 'total'>,
  searchParams: SearchParamsInput,
  basePath: string
): DataTablePaginationConfig {
  const safePageSize = pagination.pageSize > 0 ? Math.trunc(pagination.pageSize) : 1;

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

export function AnomaliesTable({
  events,
  pagination,
  searchParams,
  basePath = '/anomalies'
}: AnomaliesTableProps) {
  const tablePagination = pagination
    ? buildPaginationConfig(pagination, searchParams, basePath)
    : undefined;

  return (
    <DataTable<AnomalyEvent>
      itemKey={(event) => event.id}
      data={events}
      emptyState={<p>No anomalies detected for the selected filters.</p>}
      pagination={tablePagination}
      columns={[
        {
          key: 'anomaly_type',
          header: 'Anomaly',
          render: (event) => (
            <div className="flex flex-col">
              <span className="font-semibold text-white">{event.anomaly_type}</span>
              <span className="text-xs text-gray-400">
                Source {event.source} • Count {event.count} • Window {Math.round(event.window_seconds / 60)}m
              </span>
            </div>
          )
        },
        {
          key: 'actor',
          header: 'Actor',
          render: (event) => (
            <div className="flex flex-col">
              <span className="text-sm text-gray-200">{event.actor}</span>
              <span className="text-xs text-gray-500" title={event.first_seen}>
                First seen {relativeTime(event.first_seen)}
              </span>
            </div>
          )
        },
        {
          key: 'detected_at',
          header: 'Detected',
          render: (event) => (
            <span className="text-xs text-gray-400" title={event.detected_at}>
              {relativeTime(event.detected_at)}
            </span>
          )
        },
        {
          key: 'metadata',
          header: 'Metadata',
          render: (event) => (
            <pre className="max-h-24 overflow-y-auto whitespace-pre-wrap rounded-md bg-surface-muted/40 px-3 py-2 text-xs text-gray-200">
              {metadataPreview(event.metadata)}
            </pre>
          )
        }
      ]}
    />
  );
}
