import type { Metadata } from 'next';
import { fetchScans, fetchTargets } from '@/lib/api';
import { ScansTable } from '@/components/ScansTable';
import { ScanLaunchForm } from '@/components/ScanLaunchForm';
import type { Target } from '@/lib/types';

export const metadata: Metadata = {
  title: 'Scans | Medusa Operations Console'
};

export default async function ScansPage() {
  let error: string | null = null;
  let scans: Awaited<ReturnType<typeof fetchScans>> = [];
  let targets: Target[] = [];
  let targetError: string | null = null;

  try {
    scans = await fetchScans();
  } catch (err) {
    error = err instanceof Error ? err.message : 'Failed to load scans.';
  }

  try {
    targets = await fetchTargets();
  } catch (err) {
    targetError = err instanceof Error ? err.message : 'Failed to load targets.';
  }

  return (
    <section className="space-y-4">
      <header className="flex flex-col gap-2">
        <div>
          <h2 className="text-2xl font-semibold text-white">Controller Scans</h2>
          <p className="text-sm text-gray-400">
            Live view of queued, running, and completed scans pulled securely from the controller API.
          </p>
          <p className="text-xs text-gray-500">
            Launch new jobs with enforced presets to maintain deterministic, auditable coverage.
          </p>
        </div>
      </header>
      {targetError ? (
        <div className="card border-red-500/40 bg-red-950/40 p-4 text-sm text-red-200">
          {targetError}
        </div>
      ) : (
        <ScanLaunchForm targets={targets} />
      )}
      {error ? (
        <div className="card border-red-500/40 bg-red-950/40 p-4 text-sm text-red-200">
          {error}
        </div>
      ) : (
        <ScansTable scans={scans} />
      )}
    </section>
  );
}
