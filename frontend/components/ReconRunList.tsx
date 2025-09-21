import { formatDistanceToNow } from 'date-fns';
import type { ReconRun } from '@/lib/types';

function relativeTime(value: string): string {
  return formatDistanceToNow(new Date(value), { addSuffix: true });
}

export function ReconRunList({ runs }: { runs: ReconRun[] }) {
  return (
    <div className="card space-y-4 p-6">
      <header className="space-y-1">
        <h3 className="text-lg font-semibold text-white">Recent Recon Runs</h3>
        <p className="text-sm text-gray-400">
          Active recon jobs record tool inputs, authorized scope, and observation counts. Use this list to validate job
          execution against customer approvals.
        </p>
      </header>

      {runs.length === 0 ? (
        <p className="text-sm text-gray-500">No recon jobs have been executed yet.</p>
      ) : (
        <div className="space-y-4">
          {runs.map((run) => (
            <article key={run.id} className="rounded-lg border border-surface-muted/60 bg-surface-muted/20 p-4">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <p className="text-sm font-semibold text-white">{run.source}</p>
                  <p className="text-xs text-gray-400">Job {run.job_id}</p>
                </div>
                <span
                  className={`inline-flex items-center rounded-full px-3 py-1 text-xs font-semibold uppercase tracking-wide ${
                    run.status === 'completed'
                      ? 'bg-emerald-500/10 text-emerald-300'
                      : run.status === 'failed'
                        ? 'bg-rose-500/10 text-rose-200'
                        : 'bg-surface-muted/60 text-gray-300'
                  }`}
                >
                  {run.status}
                </span>
              </div>

              <dl className="mt-3 grid grid-cols-1 gap-3 text-xs text-gray-300 sm:grid-cols-2">
                <div>
                  <dt className="text-gray-500">Mode</dt>
                  <dd className="font-medium uppercase tracking-wide">{run.mode}</dd>
                </div>
                <div>
                  <dt className="text-gray-500">Observations</dt>
                  <dd className="font-medium">{run.observation_count}</dd>
                </div>
                <div>
                  <dt className="text-gray-500">Retrieved</dt>
                  <dd title={run.retrieved_at}>{relativeTime(run.retrieved_at)}</dd>
                </div>
                <div>
                  <dt className="text-gray-500">Authorized Scopes</dt>
                  <dd className="space-y-1">
                    {run.authorized_scopes.length === 0 ? (
                      <span className="text-gray-500">None recorded</span>
                    ) : (
                      run.authorized_scopes.map((scope) => (
                        <span key={scope} className="block font-mono text-[11px]">
                          {scope}
                        </span>
                      ))
                    )}
                  </dd>
                </div>
              </dl>

              {Object.keys(run.tooling ?? {}).length > 0 ? (
                <div className="mt-3 space-y-1 text-xs text-gray-400">
                  <p className="font-semibold text-gray-300">Tooling</p>
                  <pre className="max-h-40 overflow-auto rounded bg-black/30 p-2 font-mono text-[11px] text-gray-300">
                    {JSON.stringify(run.tooling, null, 2)}
                  </pre>
                </div>
              ) : null}

              {run.targets.length > 0 ? (
                <div className="mt-3 space-y-1 text-xs text-gray-400">
                  <p className="font-semibold text-gray-300">Targets</p>
                  <ul className="space-y-1">
                    {run.targets.map((target) => (
                      <li key={JSON.stringify(target)} className="rounded bg-surface-muted/40 p-2 font-mono text-[11px]">
                        {JSON.stringify(target)}
                      </li>
                    ))}
                  </ul>
                </div>
              ) : null}
            </article>
          ))}
        </div>
      )}
    </div>
  );
}
