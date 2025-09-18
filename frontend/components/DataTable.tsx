import { ReactNode } from 'react';

interface Column<T> {
  key: string;
  header: string;
  className?: string;
  render?: (item: T) => ReactNode;
}

interface DataTableProps<T> {
  columns: Column<T>[];
  data: T[];
  emptyState?: ReactNode;
  itemKey: (item: T) => string;
}

export function DataTable<T>({ columns, data, emptyState, itemKey }: DataTableProps<T>) {
  if (data.length === 0) {
    return (
      <div className="card p-6 text-center text-sm text-gray-400">
        {emptyState ?? 'No records to display yet.'}
      </div>
    );
  }

  return (
    <div className="card overflow-hidden">
      <table className="table-grid">
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
          {data.map((item) => (
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
  );
}
