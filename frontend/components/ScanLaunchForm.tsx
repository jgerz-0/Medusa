'use client';

import { FormEvent, useMemo, useState, useTransition } from 'react';
import type { ScheduleScanResult } from '@/app/scans/actions';
import { scheduleScanAction } from '@/app/scans/actions';
import type { ValidationIssue } from '@/lib/api';
import type { Target } from '@/lib/types';

export interface ScanPreset {
  id: string;
  label: string;
  profile: string;
  description: string;
  requestedHosts: string[];
}

export const scanPresets: ScanPreset[] = [
  {
    id: 'web-baseline',
    label: 'Baseline Web Recon',
    profile: 'web-baseline',
    description:
      'Runs nuclei HTTP checks against the asset root using hardened defaults. Ideal for daily cadence validation.',
    requestedHosts: []
  },
  {
    id: 'api-deep-dive',
    label: 'API Deep Dive',
    profile: 'api-deep-dive',
    description:
      'Expands nuclei coverage to authenticated API hosts supplied in scope while enforcing rate limits for shared services.',
    requestedHosts: ['api.medusa.local']
  },
  {
    id: 'external-attack-surface',
    label: 'External Attack Surface',
    profile: 'external-attack-surface',
    description:
      'Targets internet-facing hosts with the high-signal nuclei templates used during weekly security reviews.',
    requestedHosts: ['www.medusa.local', 'portal.medusa.local']
  }
];

interface ScanLaunchFormProps {
  targets: Target[];
}

function findIssue(issues: ValidationIssue[], field: string): ValidationIssue | undefined {
  return issues.find((issue) => issue.field === field);
}

export function ScanLaunchForm({ targets }: ScanLaunchFormProps) {
  const [selectedTargetId, setSelectedTargetId] = useState('');
  const [selectedPresetId, setSelectedPresetId] = useState<string>(
    scanPresets.length > 0 ? scanPresets[0].id : ''
  );
  const [status, setStatus] = useState<'idle' | 'pending' | 'success' | 'error'>('idle');
  const [message, setMessage] = useState('');
  const [issues, setIssues] = useState<ValidationIssue[]>([]);
  const [isPending, startTransition] = useTransition();

  const selectedPreset = useMemo(() => {
    return scanPresets.find((preset) => preset.id === selectedPresetId) ?? scanPresets[0];
  }, [selectedPresetId]);

  const targetIssue = findIssue(issues, 'targetId');
  const profileIssue = findIssue(issues, 'profile');

  async function handleResult(result: ScheduleScanResult) {
    if (result.ok) {
      setStatus('success');
      setMessage(result.message);
      setIssues([]);
      return;
    }

    setStatus('error');
    setMessage(result.message);
    setIssues(result.issues ?? []);
  }

  const onSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    const preset = selectedPreset;
    if (!selectedTargetId) {
      setStatus('error');
      setMessage('Select a target within the authorized scope before launching a scan.');
      setIssues([{ field: 'targetId', message: 'Target is required.' }]);
      return;
    }

    if (!preset) {
      setStatus('error');
      setMessage('Choose a scan profile preset to continue.');
      setIssues([{ field: 'profile', message: 'Profile is required.' }]);
      return;
    }

    startTransition(() => {
      setStatus('pending');
      setMessage('Queueing scan with controller…');
      setIssues([]);

      scheduleScanAction({
        targetId: selectedTargetId,
        profile: preset.profile,
        requestedHosts: preset.requestedHosts
      })
        .then(handleResult)
        .catch((error: unknown) => {
          setStatus('error');
          setIssues([]);
          setMessage(
            error instanceof Error
              ? error.message
              : 'Unexpected error while queueing the scan request.'
          );
        });
    });
  };

  return (
    <div className="card space-y-4 p-6">
      <header className="space-y-1">
        <h3 className="text-lg font-semibold text-white">Orchestrate New Scan</h3>
        <p className="text-sm text-gray-400">
          Schedule a nuclei job against an authorized asset. Profiles lock hardened parameters so analysts stay within
          scope.
        </p>
      </header>

      <form onSubmit={onSubmit} className="space-y-4" noValidate>
        <div className="space-y-2">
          <label htmlFor="targetId" className="block text-sm font-medium text-gray-200">
            Target
          </label>
          <select
            id="targetId"
            name="targetId"
            value={selectedTargetId}
            onChange={(event) => {
              setSelectedTargetId(event.target.value);
              setIssues((prev) => prev.filter((issue) => issue.field !== 'targetId'));
              if (status === 'error') {
                setStatus('idle');
                setMessage('');
              }
            }}
            className={`w-full rounded-md border border-surface-muted/60 bg-surface-muted/40 px-3 py-2 text-sm text-gray-100 focus:border-emerald-500 focus:outline-none ${
              targetIssue ? 'border-red-500/60' : ''
            }`}
          >
            <option value="">Select an authorized target</option>
            {targets.map((target) => (
              <option key={target.id} value={target.id} disabled={!target.is_authorized}>
                {target.name} — {target.scope}
                {!target.is_authorized ? ' (unauthorized)' : ''}
              </option>
            ))}
          </select>
          {targetIssue ? (
            <p className="text-xs text-red-300">{targetIssue.message}</p>
          ) : (
            <p className="text-xs text-gray-400">
              Targets outside the authorized scope are shown but cannot be scheduled.
            </p>
          )}
        </div>

        <div className="space-y-2">
          <label htmlFor="profile" className="block text-sm font-medium text-gray-200">
            Scan Profile
          </label>
          <select
            id="profile"
            name="profile"
            value={selectedPresetId}
            onChange={(event) => {
              setSelectedPresetId(event.target.value);
              setIssues((prev) => prev.filter((issue) => issue.field !== 'profile'));
              if (status === 'error') {
                setStatus('idle');
                setMessage('');
              }
            }}
            className={`w-full rounded-md border border-surface-muted/60 bg-surface-muted/40 px-3 py-2 text-sm text-gray-100 focus:border-emerald-500 focus:outline-none ${
              profileIssue ? 'border-red-500/60' : ''
            }`}
          >
            {scanPresets.map((preset) => (
              <option key={preset.id} value={preset.id}>
                {preset.label}
              </option>
            ))}
          </select>
          <div className="space-y-1 text-xs">
            <p className="text-gray-300">{selectedPreset?.description}</p>
            {selectedPreset && selectedPreset.requestedHosts.length > 0 ? (
              <p className="text-gray-400">
                Hosts: {selectedPreset.requestedHosts.map((host) => `“${host}”`).join(', ')}
              </p>
            ) : (
              <p className="text-gray-400">Hosts are auto-derived from the target unless overridden.</p>
            )}
            {profileIssue && <p className="text-red-300">{profileIssue.message}</p>}
          </div>
        </div>

        <div className="flex items-center justify-between">
          <button
            type="submit"
            className="inline-flex items-center rounded-md bg-emerald-600 px-4 py-2 text-sm font-semibold text-white transition hover:bg-emerald-500 disabled:cursor-not-allowed disabled:bg-emerald-800"
            disabled={isPending}
          >
            {isPending ? 'Queueing…' : 'Queue Scan'}
          </button>
          <span className="text-xs text-gray-500">
            Controller requests include audit metadata for SOC review.
          </span>
        </div>
      </form>

      {status !== 'idle' && (
        <div
          role="status"
          aria-live="polite"
          className={`rounded-md border px-3 py-2 text-sm ${
            status === 'success'
              ? 'border-emerald-600/60 bg-emerald-900/30 text-emerald-200'
              : status === 'pending'
                ? 'border-sky-600/60 bg-sky-900/30 text-sky-200'
                : 'border-red-600/60 bg-red-900/30 text-red-200'
          }`}
        >
          {message}
          {status === 'error' && issues.length > 0 && (
            <ul className="mt-2 list-disc space-y-1 pl-5 text-xs">
              {issues.map((issue) => (
                <li key={`${issue.field}-${issue.message}`}>{issue.field}: {issue.message}</li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}
