import type { FindingsTimelineBucket } from '@/lib/types';

function formatDate(value: string) {
  const date = new Date(value);
  return date.toLocaleDateString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric'
  });
}

export function FindingsTimeline({ buckets }: { buckets: FindingsTimelineBucket[] }) {
  if (buckets.length === 0) {
    return (
      <div className="card border-surface-muted/60 bg-surface-muted/10 p-4 text-sm text-gray-400">
        Timeline not available for the selected filters.
      </div>
    );
  }

  return (
    <section className="card border-surface-muted/60 bg-surface-muted/10 p-4">
      <header className="mb-3 flex items-center justify-between">
        <div>
          <h3 className="text-sm font-semibold uppercase tracking-wide text-gray-300">
            Timeline
          </h3>
          <p className="text-xs text-gray-500">
            Per-day aggregation of the validation workflow (open → pending validation → acknowledged or
            invalidated → resolved) across filtered findings.
          </p>
        </div>
      </header>
      <div className="max-h-72 overflow-y-auto">
        <table className="w-full text-left text-xs text-gray-300">
          <thead className="uppercase tracking-wide text-gray-500">
            <tr>
              <th className="px-2 py-2">Date</th>
              <th className="px-2 py-2 text-right">Open</th>
              <th className="px-2 py-2 text-right">Pending Validation</th>
              <th className="px-2 py-2 text-right">Acknowledged</th>
              <th className="px-2 py-2 text-right">Invalidated</th>
              <th className="px-2 py-2 text-right">Resolved</th>
              <th className="px-2 py-2 text-right">Total</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-surface-muted/50">
            {buckets.map((bucket) => (
              <tr key={bucket.date}>
                <td className="px-2 py-2 font-mono text-gray-200">{formatDate(bucket.date)}</td>
                <td className="px-2 py-2 text-right text-gray-100">{bucket.open}</td>
                <td className="px-2 py-2 text-right text-indigo-200/80">{bucket.pending_validation}</td>
                <td className="px-2 py-2 text-right text-amber-300/80">{bucket.acknowledged}</td>
                <td className="px-2 py-2 text-right text-rose-300/80">{bucket.invalidated}</td>
                <td className="px-2 py-2 text-right text-emerald-300/80">{bucket.resolved}</td>
                <td className="px-2 py-2 text-right text-white">{bucket.total}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
