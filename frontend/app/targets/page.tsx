import type { Metadata } from 'next';
import { fetchTargets } from '@/lib/api';
import { TargetRegistrationForm } from '@/components/TargetRegistrationForm';
import { TargetsTable } from '@/components/TargetsTable';
import { RequiredRolesNotice } from '@/components/RequiredRolesNotice';
import { ROLE_TARGETS_READ, ROLE_TARGETS_WRITE } from '@/lib/rbac';

export const metadata: Metadata = {
  title: 'Targets | Medusa Operations Console'
};

export default async function TargetsPage() {
  let targets: Awaited<ReturnType<typeof fetchTargets>> = [];
  let error: string | null = null;

  try {
    targets = await fetchTargets();
  } catch (err) {
    error = err instanceof Error ? err.message : 'Failed to load targets.';
  }

  return (
    <section className="space-y-6">
      <header className="space-y-2">
        <div>
          <h2 className="text-2xl font-semibold text-white">Authorized Targets Registry</h2>
          <p className="text-sm text-gray-400">
            Maintain the definitive list of in-scope assets. Controllers enforce scans against this inventory to uphold
            engagement guardrails.
          </p>
          <p className="text-xs text-gray-500">
            Every change is audited; review carefully before onboarding or removing a target.
          </p>
        </div>
        <RequiredRolesNotice
          sections={[
            {
              title: 'Review target inventory',
              description: 'Loads the authorized scope catalog to validate controller state before scheduling scans.',
              roles: [ROLE_TARGETS_READ]
            },
            {
              title: 'Register or update targets',
              description: 'Allows onboarding new assets or adjusting authorization flags for existing scope.',
              roles: [ROLE_TARGETS_WRITE]
            }
          ]}
        />
      </header>

      <TargetRegistrationForm />

      {error ? (
        <div className="card border border-red-500/40 bg-red-950/40 p-4 text-sm text-red-200">{error}</div>
      ) : (
        <TargetsTable targets={targets} />
      )}
    </section>
  );
}
