import clsx from 'clsx';
import { RBAC_DOCS_URL } from '@/lib/rbac';
import type { ControllerRole } from '@/lib/rbac';

export interface RoleRequirement {
  title: string;
  roles: ControllerRole[];
  description?: string;
}

export interface RequiredRolesNoticeProps {
  sections: RoleRequirement[];
  className?: string;
  docsUrl?: string;
}

function uniqueRoles(sections: RoleRequirement[]): ControllerRole[] {
  const roleSet = new Set<ControllerRole>();
  for (const section of sections) {
    for (const role of section.roles) {
      roleSet.add(role);
    }
  }
  return Array.from(roleSet);
}

interface InlineRoleBadgesProps {
  sections: RoleRequirement[];
  className?: string;
  label?: string;
}

export function InlineRoleBadges({ sections, className, label = 'Controller RBAC' }: InlineRoleBadgesProps) {
  const roles = uniqueRoles(sections);
  if (roles.length === 0) {
    return null;
  }

  return (
    <div
      className={clsx(
        'flex flex-wrap items-center gap-2 text-[11px] uppercase tracking-wide text-emerald-300',
        className
      )}
    >
      <span className="font-semibold">{label}</span>
      <ul className="flex flex-wrap gap-1">
        {roles.map((role) => (
          <li
            key={role}
            className="rounded bg-emerald-700/40 px-2 py-0.5 text-[0.65rem] font-semibold text-emerald-100"
          >
            {role}
          </li>
        ))}
      </ul>
    </div>
  );
}

export function RequiredRolesNotice({
  sections,
  className,
  docsUrl = RBAC_DOCS_URL
}: RequiredRolesNoticeProps) {
  return (
    <div
      className={clsx(
        'rounded-md border border-emerald-500/50 bg-emerald-950/40 p-4 text-sm text-emerald-100 shadow-sm',
        className
      )}
      role="note"
      aria-label="Required RBAC roles"
    >
      <div className="flex items-start gap-3">
        <span
          aria-hidden="true"
          className="mt-1 inline-flex h-9 w-9 items-center justify-center rounded-full bg-emerald-500/20 text-emerald-300"
        >
          <svg
            className="h-4 w-4"
            xmlns="http://www.w3.org/2000/svg"
            viewBox="0 0 20 20"
            fill="currentColor"
          >
            <path d="M10 2a4 4 0 00-4 4v2H5a2 2 0 00-2 2v5a3 3 0 003 3h8a3 3 0 003-3v-5a2 2 0 00-2-2h-1V6a4 4 0 00-4-4zm-2 4a2 2 0 114 0v2H8V6zm2 5a1.5 1.5 0 011.5 1.5v1a1.5 1.5 0 11-3 0v-1A1.5 1.5 0 0110 11z" />
          </svg>
        </span>
        <div className="flex-1 space-y-3">
          <div className="flex flex-wrap items-center gap-2 text-xs uppercase tracking-wide text-emerald-300">
            <span className="font-semibold">Controller RBAC required</span>
            <span
              className="text-emerald-200/80"
              title="Review docs/RBAC.md#ui-role-requirements for controller scope definitions."
            >
              <a
                href={docsUrl}
                target="_blank"
                rel="noreferrer"
                className="font-medium text-emerald-200 underline decoration-dotted decoration-emerald-400 transition hover:text-emerald-100"
              >
                scope matrix
              </a>
            </span>
          </div>
          <p className="text-xs text-emerald-200/80">
            The controller enforces these roles before returning data or accepting state changes. Missing scopes surface audit
            log denials for incident response.
          </p>
          <div className="grid gap-3 sm:grid-cols-2">
            {sections.map((section) => (
              <div
                key={section.title}
                className="rounded-md border border-emerald-500/40 bg-emerald-900/30 p-3 shadow-inner"
              >
                <p className="text-sm font-semibold text-emerald-100">{section.title}</p>
                {section.description ? (
                  <p className="mt-1 text-xs text-emerald-200/70">{section.description}</p>
                ) : null}
                <ul className="mt-2 flex flex-wrap gap-2 text-xs font-mono uppercase tracking-wide text-emerald-200">
                  {section.roles.map((role) => (
                    <li
                      key={role}
                      className="rounded bg-emerald-700/40 px-2 py-1 text-[0.7rem] font-semibold text-emerald-100"
                    >
                      {role}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
