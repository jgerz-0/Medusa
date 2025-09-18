import type { Metadata } from 'next';
import { fetchScans } from '@/lib/api';
import { ScansTable } from '@/components/ScansTable';

export const metadata: Metadata = {
  title: 'Scans | Medusa Operations Console'
};

export default async function ScansPage() {
  let error: string | null = null;
  let scans: Awaited<ReturnType<typeof fetchScans>> = [];

  try {
    scans = await fetchScans();
  } catch (err) {
    error = err instanceof Error ? err.message : 'Failed to load scans.';
  }

  return (
    <section className="space-y-4">
      <header className="flex flex-col gap-2">
        <div>
          <h2 className="text-2xl font-semibold text-white">Controller Scans</h2>
          <p className="text-sm text-gray-400">
            Live view of queued, running, and completed scans pulled securely from the controller API.
          </p>
        </div>
      </header>
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
