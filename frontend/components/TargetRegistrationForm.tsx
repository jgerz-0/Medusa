'use client';

import { useEffect, useMemo, useRef } from 'react';
import { useFormState, useFormStatus } from 'react-dom';
import { createTargetAction, initialCreateTargetState } from '@/app/targets/actions';
import type { ValidationIssue } from '@/lib/api';

function findIssue(issues: ValidationIssue[], ...fields: string[]): ValidationIssue | undefined {
  return issues.find((issue) => fields.includes(issue.field));
}

function SubmitButton() {
  const { pending } = useFormStatus();

  return (
    <button
      type="submit"
      className="inline-flex items-center rounded-md bg-emerald-600 px-4 py-2 text-sm font-medium text-white transition hover:bg-emerald-500 disabled:cursor-not-allowed disabled:bg-emerald-800/60"
      disabled={pending}
    >
      {pending ? 'Registering…' : 'Register Target'}
    </button>
  );
}

export function TargetRegistrationForm() {
  const formRef = useRef<HTMLFormElement>(null);
  const [state, formAction] = useFormState(createTargetAction, initialCreateTargetState);

  useEffect(() => {
    if (state.shouldReset) {
      formRef.current?.reset();
    }
  }, [state.shouldReset]);

  const nameIssue = useMemo(() => findIssue(state.issues, 'name'), [state.issues]);
  const scopeIssue = useMemo(() => findIssue(state.issues, 'scope'), [state.issues]);
  const authorizationIssue = useMemo(
    () => findIssue(state.issues, 'isAuthorized', 'is_authorized'),
    [state.issues]
  );

  const messageStyles =
    state.status === 'success'
      ? 'border-emerald-500/60 bg-emerald-950/40 text-emerald-200'
      : 'border-red-500/40 bg-red-950/40 text-red-200';

  return (
    <div className="card space-y-4 p-6">
      <header className="space-y-1">
        <h3 className="text-lg font-semibold text-white">Register Authorized Targets</h3>
        <p className="text-sm text-gray-400">
          Define the assets cleared for engagement. Controller enforcement relies on this list to prevent out-of-scope
          scanning.
        </p>
      </header>

      {state.message ? (
        <div className={`rounded-md border px-3 py-2 text-sm ${messageStyles}`}>{state.message}</div>
      ) : null}

      <form ref={formRef} action={formAction} className="space-y-4" noValidate>
        <div className="space-y-2">
          <label htmlFor="name" className="block text-sm font-medium text-gray-200">
            Target Name
          </label>
          <input
            id="name"
            name="name"
            type="text"
            placeholder="Production Portal"
            className={`w-full rounded-md border border-surface-muted/60 bg-surface-muted/40 px-3 py-2 text-sm text-gray-100 focus:border-emerald-500 focus:outline-none ${
              nameIssue ? 'border-red-500/60' : ''
            }`}
            aria-describedby={nameIssue ? 'target-name-error' : undefined}
            aria-invalid={nameIssue ? 'true' : 'false'}
          />
          {nameIssue ? (
            <p id="target-name-error" className="text-xs text-red-300">
              {nameIssue.message}
            </p>
          ) : null}
        </div>

        <div className="space-y-2">
          <label htmlFor="scope" className="block text-sm font-medium text-gray-200">
            Scope
          </label>
          <input
            id="scope"
            name="scope"
            type="text"
            placeholder="https://portal.medusa.local"
            className={`w-full rounded-md border border-surface-muted/60 bg-surface-muted/40 px-3 py-2 text-sm text-gray-100 focus:border-emerald-500 focus:outline-none ${
              scopeIssue ? 'border-red-500/60' : ''
            }`}
            aria-describedby={scopeIssue ? 'target-scope-error' : undefined}
            aria-invalid={scopeIssue ? 'true' : 'false'}
          />
          {scopeIssue ? (
            <p id="target-scope-error" className="text-xs text-red-300">
              {scopeIssue.message}
            </p>
          ) : null}
        </div>

        <div className="flex items-start gap-3 rounded-lg border border-surface-muted/60 bg-surface-muted/20 p-4">
          <input
            id="is_authorized"
            name="is_authorized"
            type="checkbox"
            value="true"
            defaultChecked
            className="mt-1 h-4 w-4 rounded border-surface-muted/60 bg-surface-muted/40 text-emerald-500 focus:ring-emerald-500"
            aria-describedby={authorizationIssue ? 'target-authorization-error' : 'target-authorization-hint'}
          />
          <div className="space-y-1">
            <label htmlFor="is_authorized" className="text-sm font-medium text-gray-200">
              Authorized engagement scope
            </label>
            <p id="target-authorization-hint" className="text-xs text-gray-400">
              Uncheck to register an out-of-scope asset for monitoring without enabling scans.
            </p>
            {authorizationIssue ? (
              <p id="target-authorization-error" className="text-xs text-red-300">
                {authorizationIssue.message}
              </p>
            ) : null}
          </div>
        </div>

        <div className="flex items-center justify-end gap-3">
          <SubmitButton />
        </div>
      </form>
    </div>
  );
}
