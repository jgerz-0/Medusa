import { formatDistanceToNow } from 'date-fns';
import { DataTable } from './DataTable';
import type { Target } from '@/lib/types';

function relativeTime(value: string) {
  return formatDistanceToNow(new Date(value), { addSuffix: true });
}

export function TargetsTable({ targets }: { targets: Target[] }) {
  return (
    <DataTable<Target>
      itemKey={(target) => target.id}
      data={targets}
      emptyState={<p>No targets have been registered yet.</p>}
      columns={[
        {
          key: 'name',
          header: 'Name',
          render: (target) => (
            <div>
              <p className="font-semibold text-white">{target.name}</p>
              <p className="text-xs text-gray-400">{target.id}</p>
            </div>
          )
        },
        {
          key: 'scope',
          header: 'Scope',
          render: (target) => (
            <span className="font-mono text-xs text-gray-300" title={target.scope}>
              {target.scope}
            </span>
          )
        },
        {
          key: 'is_authorized',
          header: 'Authorization',
          render: (target) => (
            <span
              className={`inline-flex items-center rounded-full px-2 py-1 text-xs font-medium ${
                target.is_authorized
                  ? 'bg-emerald-500/10 text-emerald-300'
                  : 'bg-amber-500/10 text-amber-300'
              }`}
            >
              {target.is_authorized ? 'Authorized' : 'Out of Scope'}
            </span>
          )
        },
        {
          key: 'created_at',
          header: 'Registered',
          render: (target) => (
            <span className="text-xs text-gray-400" title={target.created_at}>
              {relativeTime(target.created_at)}
            </span>
          )
        },
        {
          key: 'updated_at',
          header: 'Last Updated',
          render: (target) => (
            <span className="text-xs text-gray-400" title={target.updated_at}>
              {relativeTime(target.updated_at)}
            </span>
          )
        }
      ]}
    />
  );
}
