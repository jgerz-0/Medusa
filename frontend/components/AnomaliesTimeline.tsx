import { formatDistanceToNow } from 'date-fns';
import type { AnomalyEvent } from '@/lib/types';

function formatTimestamp(value: string) {
  return formatDistanceToNow(new Date(value), { addSuffix: true });
}

function summarizeMetadata(metadata: Record<string, unknown>): string {
  const entries = Object.entries(metadata ?? {});
  if (entries.length === 0) {
    return 'No metadata provided';
  }

  const summary = entries.slice(0, 3).map(([key, value]) => {
    if (value === null || value === undefined) {
      return `${key}: null`;
    }

    if (typeof value === 'object') {
      return `${key}: [object]`;
    }

    const text = String(value);
    return text.length > 40 ? `${key}: ${text.slice(0, 40)}…` : `${key}: ${text}`;
  });

  return summary.join(', ');
}

interface AnomaliesTimelineProps {
  events: AnomalyEvent[];
  limit?: number;
}

export function AnomaliesTimeline({ events, limit = 20 }: AnomaliesTimelineProps) {
  if (!events || events.length === 0) {
    return (
      <div className="card border-surface-muted/60 bg-surface-muted/10 p-4 text-sm text-gray-400">
        No anomaly events available for the selected scope.
      </div>
    );
  }

  const ordered = [...events].sort((a, b) => {
    return new Date(b.detected_at).getTime() - new Date(a.detected_at).getTime();
  });

  const sliced = ordered.slice(0, limit);

  return (
    <section className="card border-surface-muted/60 bg-surface-muted/10 p-4">
      <header className="mb-3 flex items-center justify-between">
        <div>
          <h3 className="text-sm font-semibold uppercase tracking-wide text-gray-300">Recent Activity</h3>
          <p className="text-xs text-gray-500">Chronological view of anomaly callbacks recorded by the controller.</p>
        </div>
      </header>
      <ol className="space-y-3">
        {sliced.map((event) => (
          <li key={event.id} className="rounded-lg border border-surface-muted/60 bg-surface-muted/20 p-3">
            <div className="flex flex-col gap-1">
              <div className="flex flex-col">
                <span className="text-sm font-semibold text-white">{event.anomaly_type}</span>
                <span className="text-xs text-gray-400">
                  Actor {event.actor} • Source {event.source} • Count {event.count}
                </span>
              </div>
              <div className="flex flex-col text-xs text-gray-500">
                <span title={event.detected_at}>Detected {formatTimestamp(event.detected_at)}</span>
                <span title={event.first_seen}>First seen {formatTimestamp(event.first_seen)}</span>
                <span title={event.last_seen}>Last seen {formatTimestamp(event.last_seen)}</span>
              </div>
              <p className="text-xs text-gray-300">{summarizeMetadata(event.metadata)}</p>
            </div>
          </li>
        ))}
      </ol>
    </section>
  );
}
