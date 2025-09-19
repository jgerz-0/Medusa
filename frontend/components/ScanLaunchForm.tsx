'use client';

import { FormEvent, useMemo, useState, useTransition } from 'react';
import type { ScheduleScanResult, SupportedScanner } from '@/app/scans/actions';
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

const zapPolicies: { id: 'baseline' | 'full'; label: string; description: string }[] = [
  {
    id: 'baseline',
    label: 'Baseline Passive',
    description: 'Passive crawl against production with request throttling and no active attacks.'
  },
  {
    id: 'full',
    label: 'Full Active',
    description: 'Enable full attack mode for change-controlled windows. Higher risk of production impact.'
  }
];

const zapModes: { id: 'baseline' | 'full'; label: string; description: string }[] = [
  {
    id: 'baseline',
    label: 'Baseline Mode',
    description: 'Passive spidering with minimal side effects.'
  },
  {
    id: 'full',
    label: 'Full Mode',
    description: 'Active scan modules are enabled. Coordinate with SRE before use.'
  }
];

const sqlmapLevels = [1, 2, 3, 4, 5] as const;
const sqlmapRisks = [0, 1, 2, 3] as const;
const defaultZapRateLimit = '5';
const defaultSqlmapLevel: (typeof sqlmapLevels)[number] = 1;
const defaultSqlmapRisk: (typeof sqlmapRisks)[number] = 1;

interface ScanLaunchFormProps {
  targets: Target[];
}

function findIssue(issues: ValidationIssue[], field: string): ValidationIssue | undefined {
  return issues.find((issue) => issue.field === field);
}

export function ScanLaunchForm({ targets }: ScanLaunchFormProps) {
  const [selectedTargetId, setSelectedTargetId] = useState('');
  const [selectedScanner, setSelectedScanner] = useState<SupportedScanner>('nuclei');
  const [selectedPresetId, setSelectedPresetId] = useState<string>(
    scanPresets.length > 0 ? scanPresets[0].id : ''
  );
  const [zapPolicyId, setZapPolicyId] = useState<(typeof zapPolicies)[number]['id']>('baseline');
  const [zapModeId, setZapModeId] = useState<(typeof zapModes)[number]['id']>('baseline');
  const [zapRateLimit, setZapRateLimit] = useState(defaultZapRateLimit);
  const [sqlmapLevel, setSqlmapLevel] = useState<(typeof sqlmapLevels)[number]>(defaultSqlmapLevel);
  const [sqlmapRisk, setSqlmapRisk] = useState<(typeof sqlmapRisks)[number]>(defaultSqlmapRisk);
  const [sqlmapDelay, setSqlmapDelay] = useState('0');
  const [status, setStatus] = useState<'idle' | 'pending' | 'success' | 'error'>('idle');
  const [message, setMessage] = useState('');
  const [issues, setIssues] = useState<ValidationIssue[]>([]);
  const [isPending, startTransition] = useTransition();

  const selectedTarget = useMemo(() => {
    return targets.find((target) => target.id === selectedTargetId) ?? null;
  }, [targets, selectedTargetId]);

  const selectedPreset = useMemo(() => {
    if (selectedScanner !== 'nuclei') {
      return null;
    }
    return scanPresets.find((preset) => preset.id === selectedPresetId) ?? scanPresets[0] ?? null;
  }, [selectedPresetId, selectedScanner]);

  const activeZapPolicy = useMemo(() => {
    return zapPolicies.find((option) => option.id === zapPolicyId) ?? zapPolicies[0] ?? null;
  }, [zapPolicyId]);

  const activeZapMode = useMemo(() => {
    return zapModes.find((option) => option.id === zapModeId) ?? zapModes[0] ?? null;
  }, [zapModeId]);

  const requiresHttpScope = selectedScanner === 'zap' || selectedScanner === 'sqlmap';
  const targetSupportsHttp =
    !selectedTarget || selectedTarget.scope.startsWith('http://') || selectedTarget.scope.startsWith('https://');

  const targetIssue = findIssue(issues, 'targetId');
  const profileIssue = findIssue(issues, 'profile');
  const scannerIssue = findIssue(issues, 'scanner');
  const policyIssue = findIssue(issues, 'policy');
  const modeIssue = findIssue(issues, 'mode');
  const levelIssue = findIssue(issues, 'level');
  const riskIssue = findIssue(issues, 'risk');

  const clearIssue = (field: string) => {
    setIssues((prev) => prev.filter((issue) => issue.field !== field));
  };

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

    if (!selectedTargetId) {
      setStatus('error');
      setMessage('Select a target within the authorized scope before launching a scan.');
      setIssues([{ field: 'targetId', message: 'Target is required.' }]);
      return;
    }

    const parameters: Record<string, unknown> = {};

    if (selectedScanner === 'nuclei') {
      if (!selectedPreset) {
        setStatus('error');
        setMessage('Choose a scan profile preset to continue.');
        setIssues([{ field: 'profile', message: 'Profile is required.' }]);
        return;
      }
      parameters.profile = selectedPreset.profile;
      if (selectedPreset.requestedHosts.length > 0) {
        parameters.requested_hosts = selectedPreset.requestedHosts;
      }
    } else if (selectedScanner === 'zap') {
      parameters.policy = zapPolicyId;
      parameters.mode = zapModeId;
      parameters.rate_limit = zapRateLimit;
    } else if (selectedScanner === 'sqlmap') {
      parameters.level = sqlmapLevel;
      parameters.risk = sqlmapRisk;
      if (sqlmapDelay.trim() !== '') {
        parameters.request_delay = sqlmapDelay;
      }
    }

    setStatus('pending');
    setMessage('Queueing scan with controller…');
    setIssues([]);

    startTransition(() => {
      scheduleScanAction({
        targetId: selectedTargetId,
        targetScope: selectedTarget?.scope,
        scanner: selectedScanner,
        parameters
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
          Schedule a scanner job against an authorized asset. Presets lock hardened nuclei, ZAP, and SQLMap parameters so
          analysts stay within scope.
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
              clearIssue('targetId');
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
          {requiresHttpScope && selectedTarget && !targetSupportsHttp && (
            <p className="text-xs text-amber-300">
              ZAP and SQLMap require an HTTP or HTTPS scope. Select an HTTP(S) target to continue.
            </p>
          )}
        </div>

        <div className="space-y-2">
          <label htmlFor="scanner" className="block text-sm font-medium text-gray-200">
            Scanner
          </label>
          <select
            id="scanner"
            name="scanner"
            value={selectedScanner}
            onChange={(event) => {
              const nextScanner = event.target.value as SupportedScanner;
              setSelectedScanner(nextScanner);
              clearIssue('scanner');
              setStatus('idle');
              setMessage('');
              setIssues((prev) =>
                prev.filter((issue) => !['profile', 'policy', 'mode', 'level', 'risk'].includes(issue.field))
              );
              if (nextScanner === 'nuclei') {
                const defaultPreset = scanPresets[0];
                if (defaultPreset) {
                  setSelectedPresetId(defaultPreset.id);
                }
              }
              if (nextScanner === 'zap') {
                setZapPolicyId(zapPolicies[0]?.id ?? 'baseline');
                setZapModeId(zapModes[0]?.id ?? 'baseline');
                setZapRateLimit(defaultZapRateLimit);
              }
              if (nextScanner === 'sqlmap') {
                setSqlmapLevel(defaultSqlmapLevel);
                setSqlmapRisk(defaultSqlmapRisk);
                setSqlmapDelay('0');
              }
            }}
            className={`w-full rounded-md border border-surface-muted/60 bg-surface-muted/40 px-3 py-2 text-sm text-gray-100 focus:border-emerald-500 focus:outline-none ${
              scannerIssue ? 'border-red-500/60' : ''
            }`}
          >
            <option value="nuclei">Nuclei (template-driven HTTP checks)</option>
            <option value="zap">OWASP ZAP (passive or active web scan)</option>
            <option value="sqlmap">SQLMap (injection validation)</option>
          </select>
          {scannerIssue ? (
            <p className="text-xs text-red-300">{scannerIssue.message}</p>
          ) : (
            <p className="text-xs text-gray-400">
              Choose the worker. ZAP and SQLMap enforce HTTP(S) targets; nuclei honors optional host overrides.
            </p>
          )}
        </div>

        {selectedScanner === 'nuclei' && (
          <div className="space-y-2">
            <label htmlFor="profile" className="block text-sm font-medium text-gray-200">
              Nuclei Profile
            </label>
            <select
              id="profile"
              name="profile"
              value={selectedPresetId}
              onChange={(event) => {
                setSelectedPresetId(event.target.value);
                clearIssue('profile');
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
        )}

        {selectedScanner === 'zap' && (
          <div className="space-y-4">
            <div className="space-y-2">
              <label htmlFor="zapPolicy" className="block text-sm font-medium text-gray-200">
                ZAP Policy
              </label>
              <select
                id="zapPolicy"
                name="zapPolicy"
                value={zapPolicyId}
                onChange={(event) => {
                  setZapPolicyId(event.target.value as (typeof zapPolicies)[number]['id']);
                  clearIssue('policy');
                  if (status === 'error') {
                    setStatus('idle');
                    setMessage('');
                  }
                }}
                className={`w-full rounded-md border border-surface-muted/60 bg-surface-muted/40 px-3 py-2 text-sm text-gray-100 focus:border-emerald-500 focus:outline-none ${
                  policyIssue ? 'border-red-500/60' : ''
                }`}
              >
                {zapPolicies.map((policy) => (
                  <option key={policy.id} value={policy.id}>
                    {policy.label}
                  </option>
                ))}
              </select>
              <div className="space-y-1 text-xs">
                {policyIssue ? (
                  <p className="text-red-300">{policyIssue.message}</p>
                ) : (
                  <p className="text-gray-300">{activeZapPolicy?.description}</p>
                )}
              </div>
            </div>

            <div className="space-y-2">
              <label htmlFor="zapMode" className="block text-sm font-medium text-gray-200">
                ZAP Mode
              </label>
              <select
                id="zapMode"
                name="zapMode"
                value={zapModeId}
                onChange={(event) => {
                  setZapModeId(event.target.value as (typeof zapModes)[number]['id']);
                  clearIssue('mode');
                  if (status === 'error') {
                    setStatus('idle');
                    setMessage('');
                  }
                }}
                className={`w-full rounded-md border border-surface-muted/60 bg-surface-muted/40 px-3 py-2 text-sm text-gray-100 focus:border-emerald-500 focus:outline-none ${
                  modeIssue ? 'border-red-500/60' : ''
                }`}
              >
                {zapModes.map((mode) => (
                  <option key={mode.id} value={mode.id}>
                    {mode.label}
                  </option>
                ))}
              </select>
              <div className="space-y-1 text-xs">
                {modeIssue ? (
                  <p className="text-red-300">{modeIssue.message}</p>
                ) : (
                  <p className="text-gray-300">{activeZapMode?.description}</p>
                )}
              </div>
            </div>

            <div className="space-y-2">
              <label htmlFor="zapRateLimit" className="block text-sm font-medium text-gray-200">
                Rate Limit (requests/sec)
              </label>
              <input
                id="zapRateLimit"
                name="zapRateLimit"
                type="text"
                inputMode="decimal"
                value={zapRateLimit}
                onChange={(event) => {
                  setZapRateLimit(event.target.value);
                }}
                className="w-full rounded-md border border-surface-muted/60 bg-surface-muted/40 px-3 py-2 text-sm text-gray-100 focus:border-emerald-500 focus:outline-none"
              />
              <p className="text-xs text-gray-400">
                Controller defaults to 5 req/s and coerces invalid values back to the safe baseline.
              </p>
            </div>
          </div>
        )}

        {selectedScanner === 'sqlmap' && (
          <div className="space-y-4 md:grid md:grid-cols-2 md:gap-4">
            <div className="space-y-2">
              <label htmlFor="sqlmapLevel" className="block text-sm font-medium text-gray-200">
                SQLMap Level
              </label>
              <select
                id="sqlmapLevel"
                name="sqlmapLevel"
                value={sqlmapLevel}
                onChange={(event) => {
                  const levelValue = Number(event.target.value) as (typeof sqlmapLevels)[number];
                  setSqlmapLevel(levelValue);
                  clearIssue('level');
                  if (status === 'error') {
                    setStatus('idle');
                    setMessage('');
                  }
                }}
                className={`w-full rounded-md border border-surface-muted/60 bg-surface-muted/40 px-3 py-2 text-sm text-gray-100 focus:border-emerald-500 focus:outline-none ${
                  levelIssue ? 'border-red-500/60' : ''
                }`}
              >
                {sqlmapLevels.map((level) => (
                  <option key={level} value={level}>
                    Level {level}
                  </option>
                ))}
              </select>
              {levelIssue ? (
                <p className="text-xs text-red-300">{levelIssue.message}</p>
              ) : (
                <p className="text-xs text-gray-400">Higher levels expand payload coverage up to the controller cap.</p>
              )}
            </div>

            <div className="space-y-2">
              <label htmlFor="sqlmapRisk" className="block text-sm font-medium text-gray-200">
                SQLMap Risk
              </label>
              <select
                id="sqlmapRisk"
                name="sqlmapRisk"
                value={sqlmapRisk}
                onChange={(event) => {
                  const riskValue = Number(event.target.value) as (typeof sqlmapRisks)[number];
                  setSqlmapRisk(riskValue);
                  clearIssue('risk');
                  if (status === 'error') {
                    setStatus('idle');
                    setMessage('');
                  }
                }}
                className={`w-full rounded-md border border-surface-muted/60 bg-surface-muted/40 px-3 py-2 text-sm text-gray-100 focus:border-emerald-500 focus:outline-none ${
                  riskIssue ? 'border-red-500/60' : ''
                }`}
              >
                {sqlmapRisks.map((risk) => (
                  <option key={risk} value={risk}>
                    Risk {risk}
                  </option>
                ))}
              </select>
              {riskIssue ? (
                <p className="text-xs text-red-300">{riskIssue.message}</p>
              ) : (
                <p className="text-xs text-gray-400">Risk 0 is safe read-only; 3 enables aggressive payloads.</p>
              )}
            </div>

            <div className="space-y-2 md:col-span-2">
              <label htmlFor="sqlmapDelay" className="block text-sm font-medium text-gray-200">
                Request Delay (seconds, optional)
              </label>
              <input
                id="sqlmapDelay"
                name="sqlmapDelay"
                type="text"
                inputMode="decimal"
                value={sqlmapDelay}
                onChange={(event) => {
                  setSqlmapDelay(event.target.value);
                }}
                className="w-full rounded-md border border-surface-muted/60 bg-surface-muted/40 px-3 py-2 text-sm text-gray-100 focus:border-emerald-500 focus:outline-none"
              />
              <p className="text-xs text-gray-400">Use to throttle noisy targets. Blank retains the controller default.</p>
            </div>
          </div>
        )}

        <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
          <button
            type="submit"
            className="inline-flex items-center justify-center rounded-md bg-emerald-600 px-4 py-2 text-sm font-semibold text-white transition hover:bg-emerald-500 disabled:cursor-not-allowed disabled:bg-emerald-800"
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
