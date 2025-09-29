import clsx from 'clsx';
import type { FindingStatus, ScanStatus, SeverityLevel } from '@/lib/types';

type StatusKind = ScanStatus | FindingStatus | SeverityLevel;

const badgeStyles: Record<StatusKind, string> = {
  queued: 'bg-status-queued/15 text-status-queued border-status-queued/40',
  running: 'bg-status-running/15 text-status-running border-status-running/40',
  completed: 'bg-status-completed/15 text-status-completed border-status-completed/40',
  failed: 'bg-status-failed/15 text-status-failed border-status-failed/40',
  open: 'bg-status-open/15 text-status-open border-status-open/40',
  pending_validation:
    'bg-status-pending-validation/15 text-status-pending-validation border-status-pending-validation/40',
  acknowledged: 'bg-status-acknowledged/15 text-status-acknowledged border-status-acknowledged/40',
  invalidated: 'bg-status-invalidated/15 text-status-invalidated border-status-invalidated/40',
  resolved: 'bg-status-resolved/15 text-status-resolved border-status-resolved/40',
  critical: 'bg-severity-critical/15 text-severity-critical border-severity-critical/40',
  high: 'bg-severity-high/15 text-severity-high border-severity-high/40',
  medium: 'bg-severity-medium/15 text-severity-medium border-severity-medium/40',
  low: 'bg-severity-low/15 text-severity-low border-severity-low/40',
  info: 'bg-severity-info/15 text-severity-info border-severity-info/40'
};

export function StatusBadge({ value }: { value: StatusKind }) {
  return (
    <span
      className={clsx(
        'inline-flex items-center gap-1 rounded-full border px-2.5 py-0.5 text-xs font-semibold uppercase tracking-wide',
        badgeStyles[value]
      )}
      data-testid={`status-${value}`}
    >
      {value}
    </span>
  );
}
