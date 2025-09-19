import Link from 'next/link';

const severityOptions = ['critical', 'high', 'medium', 'low', 'info'];
const statusOptions = ['open', 'acknowledged', 'resolved'];

type FindingsFiltersProps = {
  searchParams?: {
    scan?: string;
    severity?: string;
    status?: string;
    tag?: string;
    assigned?: string;
    from?: string;
    to?: string;
  };
};

export function FindingsFilters({ searchParams }: FindingsFiltersProps) {
  return (
    <form className="card border-surface-muted/60 bg-surface-muted/10 px-4 py-3 text-xs" method="get">
      <div className="flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
        <div className="grid flex-1 grid-cols-1 gap-3 md:grid-cols-6">
          <label className="flex flex-col gap-1 text-[11px] uppercase tracking-wide text-gray-400">
            Scan ID
            <input
              type="text"
              name="scan"
              defaultValue={searchParams?.scan ?? ''}
              className="input"
              placeholder="scan identifier"
            />
          </label>
          <label className="flex flex-col gap-1 text-[11px] uppercase tracking-wide text-gray-400">
            Severity
            <select name="severity" defaultValue={searchParams?.severity ?? ''} className="input">
              <option value="">Any</option>
              {severityOptions.map((option) => (
                <option key={option} value={option}>
                  {option}
                </option>
              ))}
            </select>
          </label>
          <label className="flex flex-col gap-1 text-[11px] uppercase tracking-wide text-gray-400">
            Status
            <select name="status" defaultValue={searchParams?.status ?? ''} className="input">
              <option value="">Any</option>
              {statusOptions.map((option) => (
                <option key={option} value={option}>
                  {option}
                </option>
              ))}
            </select>
          </label>
          <label className="flex flex-col gap-1 text-[11px] uppercase tracking-wide text-gray-400">
            Tag
            <input
              type="text"
              name="tag"
              defaultValue={searchParams?.tag ?? ''}
              className="input"
              placeholder="workflow tag"
            />
          </label>
          <label className="flex flex-col gap-1 text-[11px] uppercase tracking-wide text-gray-400">
            Assigned To
            <input
              type="text"
              name="assigned"
              defaultValue={searchParams?.assigned ?? ''}
              className="input"
              placeholder="analyst"
            />
          </label>
          <div className="grid grid-cols-2 gap-2">
            <label className="flex flex-col gap-1 text-[11px] uppercase tracking-wide text-gray-400">
              From
              <input
                type="datetime-local"
                name="from"
                defaultValue={searchParams?.from ?? ''}
                className="input"
              />
            </label>
            <label className="flex flex-col gap-1 text-[11px] uppercase tracking-wide text-gray-400">
              To
              <input
                type="datetime-local"
                name="to"
                defaultValue={searchParams?.to ?? ''}
                className="input"
              />
            </label>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <button type="submit" className="btn btn-primary">
            Apply
          </button>
          <Link href="/findings" className="btn btn-secondary">
            Reset
          </Link>
        </div>
      </div>
    </form>
  );
}
