'use client';

import { useEffect, useMemo, useState } from 'react';
import type { ReconDiscovery, ReconRun } from '@/lib/types';
import { ReconDiscoveryTable } from './ReconDiscoveryTable';
import { ReconRunList } from './ReconRunList';
import { PromoteDiscoveryForm } from './PromoteDiscoveryForm';

export interface DiscoveryDashboardProps {
  discoveries: ReconDiscovery[];
  runs: ReconRun[];
}

export function DiscoveryDashboard({ discoveries, runs }: DiscoveryDashboardProps) {
  const prioritizedDiscovery = useMemo(() => {
    return (
      discoveries.find((item) => item.diff_status === 'scope_extension' || item.diff_status === 'unmatched') ||
      discoveries[0] ||
      null
    );
  }, [discoveries]);

  const [selectedDiscoveryId, setSelectedDiscoveryId] = useState<string | null>(
    prioritizedDiscovery?.id ?? null
  );

  useEffect(() => {
    setSelectedDiscoveryId((current) => {
      if (current && discoveries.some((item) => item.id === current)) {
        return current;
      }
      return prioritizedDiscovery?.id ?? null;
    });
  }, [discoveries, prioritizedDiscovery]);

  return (
    <div className="grid gap-6 lg:grid-cols-[2fr_1fr]">
      <div className="space-y-6">
        <ReconDiscoveryTable
          discoveries={discoveries}
          selectedDiscoveryId={selectedDiscoveryId}
          onSelect={setSelectedDiscoveryId}
        />
        <ReconRunList runs={runs} />
      </div>

      <PromoteDiscoveryForm
        discoveries={discoveries}
        selectedDiscoveryId={selectedDiscoveryId}
        onSelect={setSelectedDiscoveryId}
      />
    </div>
  );
}
