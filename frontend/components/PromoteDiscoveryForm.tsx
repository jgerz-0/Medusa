'use client';

import { useEffect, useMemo, useRef, useState } from 'react';
import { useFormState, useFormStatus } from 'react-dom';
import type { ReconDiscovery } from '@/lib/types';
import type { ValidationIssue } from '@/lib/api';
import {
  initialPromoteDiscoveryState,
  promoteDiscoveryAction
} from '@/app/discovery/actions';

interface PromoteDiscoveryFormProps {
  discoveries: ReconDiscovery[];
  selectedDiscoveryId: string | null;
  onSelect?: (discoveryId: string | null) => void;
}

const diffStatusGuidance: Record<
  ReconDiscovery['diff_status'],
  { title: string; advisory: string }
> = {
  approved: {
    title: 'Already promoted',
    advisory: 'This asset has been approved previously. Promotion will not create a duplicate target.'
  },
  in_scope: {
    title: 'Matches existing scope',
    advisory: 'Recon matched this asset to an authorized scope. Promotion is typically unnecessary.'
  },
  scope_extension: {
    title: 'Potential scope extension',
    advisory:
      'Client approval is required before expanding scope. Ensure the engagement letter authorizes onboarding this asset.'
  },
  unmatched: {
    title: 'Outside defined scope',
    advisory:
      'Do not promote without written authorization. Use this form only after validating the asset belongs to the client.'
  }
};

function findIssue(issues: ValidationIssue[], ...fields: string[]): ValidationIssue | undefined {
  return issues.find((issue) => fields.includes(issue.field));
}

function deriveDefaultTargetName(discovery: ReconDiscovery | null): string {
  if (!discovery) {
    return '';
  }

  if (discovery.metadata?.hostname && typeof discovery.metadata.hostname === 'string') {
    return discovery.metadata.hostname;
  }

  if (discovery.asset_type === 'service' && discovery.metadata?.service_name) {
    const serviceName = String(discovery.metadata.service_name);
    return `${serviceName} - ${discovery.value}`;
  }

  if (discovery.asset_type === 'url') {
    try {
      const url = new URL(discovery.value);
      return url.hostname;
    } catch {
      return discovery.value;
    }
  }

  return discovery.value;
}

function deriveDefaultScope(discovery: ReconDiscovery | null): string {
  if (!discovery) {
    return '';
  }

  if (discovery.matched_scope) {
    return discovery.matched_scope;
  }

  if (discovery.asset_type === 'url') {
    return discovery.value;
  }

  if (discovery.asset_type === 'domain' || discovery.asset_type === 'hostname') {
    return `https://${discovery.value}`;
  }

  return discovery.value;
}

function SubmitButton({ disabled }: { disabled?: boolean }) {
  const { pending } = useFormStatus();

  return (
    <button
      type="submit"
      className="inline-flex w-full items-center justify-center rounded-md bg-emerald-600 px-4 py-2 text-sm font-semibold text-white transition hover:bg-emerald-500 disabled:cursor-not-allowed disabled:bg-emerald-800/60"
      disabled={pending || disabled}
    >
      {pending ? 'Promoting…' : 'Promote to Target'}
    </button>
  );
}

export function PromoteDiscoveryForm({
  discoveries,
  selectedDiscoveryId,
  onSelect
}: PromoteDiscoveryFormProps) {
  const [state, formAction] = useFormState(promoteDiscoveryAction, initialPromoteDiscoveryState);
  const [localDiscoveryId, setLocalDiscoveryId] = useState<string>(selectedDiscoveryId ?? '');
  const [targetName, setTargetName] = useState<string>('');
  const [scope, setScope] = useState<string>('');
  const previousDiscoveryId = useRef<string | null>(null);
  const formRef = useRef<HTMLFormElement>(null);

  useEffect(() => {
    setLocalDiscoveryId(selectedDiscoveryId ?? '');
  }, [selectedDiscoveryId]);

  const selectedDiscovery = useMemo(
    () => discoveries.find((item) => item.id === localDiscoveryId) ?? null,
    [discoveries, localDiscoveryId]
  );

  const hasDiscoveries = discoveries.length > 0;
  const inputsDisabled = !localDiscoveryId;

  useEffect(() => {
    const currentId = selectedDiscovery?.id ?? null;
    if (currentId === previousDiscoveryId.current) {
      return;
    }
    previousDiscoveryId.current = currentId;
    setTargetName(deriveDefaultTargetName(selectedDiscovery));
    setScope(deriveDefaultScope(selectedDiscovery));
  }, [selectedDiscovery]);

  useEffect(() => {
    if (!state.shouldReset) {
      return;
    }
    if (formRef.current) {
      formRef.current.reset();
    }
    setTargetName(deriveDefaultTargetName(selectedDiscovery));
    setScope(deriveDefaultScope(selectedDiscovery));
  }, [state.shouldReset, selectedDiscovery]);

  const discoveryIssue = useMemo(() => findIssue(state.issues, 'discoveryId'), [state.issues]);
  const nameIssue = useMemo(() => findIssue(state.issues, 'targetName'), [state.issues]);
  const scopeIssue = useMemo(() => findIssue(state.issues, 'scope'), [state.issues]);

  const guidance = selectedDiscovery ? diffStatusGuidance[selectedDiscovery.diff_status] : null;

  return (
    <div className="card space-y-4 p-6">
      <header className="space-y-1">
        <h3 className="text-lg font-semibold text-white">Promote Discovery</h3>
        <p className="text-sm text-gray-400">
          Convert vetted recon discoveries into authorized targets. Only promote assets that the client explicitly
          approved for scanning.
        </p>
      </header>

      {state.message ? (
        <div
          className={`rounded-md border px-3 py-2 text-sm ${
            state.status === 'success'
              ? 'border-emerald-500/60 bg-emerald-950/40 text-emerald-200'
              : 'border-amber-500/40 bg-amber-950/40 text-amber-100'
          }`}
        >
          {state.message}
        </div>
      ) : null}

      <form ref={formRef} action={formAction} className="space-y-4" noValidate>
        <div className="space-y-2">
          <label htmlFor="discoveryId" className="block text-sm font-medium text-gray-200">
            Discovery
          </label>
          <select
            id="discoveryId"
            name="discoveryId"
            className={`w-full rounded-md border border-surface-muted/60 bg-surface-muted/40 px-3 py-2 text-sm text-gray-100 focus:border-emerald-500 focus:outline-none ${
              discoveryIssue ? 'border-rose-500/60' : ''
            }`}
            value={localDiscoveryId}
            onChange={(event) => {
              const value = event.target.value;
              setLocalDiscoveryId(value);
              onSelect?.(value || null);
            }}
            disabled={!hasDiscoveries}
          >
            <option value="">{hasDiscoveries ? 'Select a discovery' : 'No discoveries available'}</option>
            {discoveries.map((discovery) => (
              <option key={discovery.id} value={discovery.id}>
                {discovery.value} ({discovery.asset_type})
              </option>
            ))}
          </select>
          {discoveryIssue ? (
            <p className="text-xs text-rose-300">{discoveryIssue.message}</p>
          ) : null}
        </div>

        {selectedDiscovery ? (
          <div className="rounded-md border border-surface-muted/50 bg-surface-muted/20 p-3 text-xs text-gray-300">
            <p className="font-semibold text-white">{selectedDiscovery.value}</p>
            <p className="text-[11px] text-gray-500">Source: {selectedDiscovery.source}</p>
            {guidance ? (
              <div className="mt-2 space-y-1">
                <p className="text-[11px] uppercase tracking-wide text-amber-300">{guidance.title}</p>
                <p className="text-[11px] text-gray-400">{guidance.advisory}</p>
              </div>
            ) : null}
            <p className="mt-2 text-[11px] text-gray-500">First seen: {selectedDiscovery.first_seen}</p>
            <p className="text-[11px] text-gray-500">Last seen: {selectedDiscovery.last_seen}</p>
          </div>
        ) : null}

        <div className="space-y-2">
          <label htmlFor="targetName" className="block text-sm font-medium text-gray-200">
            Target Name
          </label>
          <input
            id="targetName"
            name="targetName"
            type="text"
            value={targetName}
            onChange={(event) => setTargetName(event.target.value)}
            placeholder="Production portal"
            className={`w-full rounded-md border border-surface-muted/60 bg-surface-muted/40 px-3 py-2 text-sm text-gray-100 focus:border-emerald-500 focus:outline-none ${
              nameIssue ? 'border-rose-500/60' : ''
            }`}
            aria-invalid={nameIssue ? 'true' : 'false'}
            aria-describedby={nameIssue ? 'target-name-error' : undefined}
            disabled={inputsDisabled}
          />
          {nameIssue ? (
            <p id="target-name-error" className="text-xs text-rose-300">
              {nameIssue.message}
            </p>
          ) : null}
        </div>

        <div className="space-y-2">
          <label htmlFor="scope" className="block text-sm font-medium text-gray-200">
            Authorized Scope
          </label>
          <input
            id="scope"
            name="scope"
            type="text"
            value={scope}
            onChange={(event) => setScope(event.target.value)}
            placeholder="https://portal.example.com"
            className={`w-full rounded-md border border-surface-muted/60 bg-surface-muted/40 px-3 py-2 text-sm text-gray-100 focus:border-emerald-500 focus:outline-none ${
              scopeIssue ? 'border-rose-500/60' : ''
            }`}
            aria-invalid={scopeIssue ? 'true' : 'false'}
            aria-describedby={scopeIssue ? 'target-scope-error' : undefined}
            disabled={inputsDisabled}
          />
          <p className="text-[11px] text-gray-500">
            Scope must remain within the client-approved boundary. Leave blank to use the controller&apos;s recommended
            scope.
          </p>
          {scopeIssue ? (
            <p id="target-scope-error" className="text-xs text-rose-300">
              {scopeIssue.message}
            </p>
          ) : null}
        </div>

        <div className="pt-2">
          <SubmitButton disabled={!localDiscoveryId} />
        </div>
      </form>
    </div>
  );
}
