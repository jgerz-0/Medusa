import type { Metadata } from 'next';
import { DiscoveryDashboard } from '@/components/DiscoveryDashboard';
import { fetchReconDiscoveries, fetchReconRuns } from '@/lib/api';

export const metadata: Metadata = {
  title: 'Discovery | Medusa Operations Console'
};

export default async function DiscoveryPage() {
  let discoveries: Awaited<ReturnType<typeof fetchReconDiscoveries>> = [];
  let runs: Awaited<ReturnType<typeof fetchReconRuns>> = [];
  let discoveryError: string | null = null;
  let runsError: string | null = null;

  try {
    discoveries = await fetchReconDiscoveries();
  } catch (error) {
    discoveryError =
      error instanceof Error
        ? error.message
        : 'Failed to load recon discoveries. Ensure the controller API is reachable.';
  }

  try {
    runs = await fetchReconRuns(25);
  } catch (error) {
    runsError =
      error instanceof Error
        ? error.message
        : 'Failed to load recon run history. Ensure the controller API is reachable.';
  }

  const showDashboard = !discoveryError && !runsError;

  return (
    <section className="space-y-6">
      <header className="space-y-2">
        <div>
          <h2 className="text-2xl font-semibold text-white">Discovery Intelligence</h2>
          <p className="text-sm text-gray-400">
            Review subdomain, service, and host intelligence collected by the recon worker. Every asset is diffed against
            the authorized target registry to guardrail scope creep.
          </p>
          <p className="text-xs text-gray-500">
            Promote discoveries only after confirming engagement approval. All promotions are audited within the
            controller.
          </p>
        </div>
      </header>

      {discoveryError ? (
        <div className="rounded-md border border-rose-500/60 bg-rose-950/40 p-4 text-sm text-rose-200">
          {discoveryError}
        </div>
      ) : null}

      {runsError ? (
        <div className="rounded-md border border-amber-500/60 bg-amber-950/40 p-4 text-sm text-amber-100">
          {runsError}
        </div>
      ) : null}

      {showDashboard ? (
        <DiscoveryDashboard discoveries={discoveries} runs={runs} />
      ) : (
        <p className="text-sm text-gray-400">
          Resolve the API connectivity issues above to review recon telemetry.
        </p>
      )}
    </section>
  );
}
