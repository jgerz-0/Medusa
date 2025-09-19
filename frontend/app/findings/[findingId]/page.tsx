import Link from 'next/link';
import { notFound } from 'next/navigation';
import { fetchFinding } from '@/lib/api';
import type { Metadata } from 'next';
import { StatusBadge } from '@/components/StatusBadge';

interface FindingDetailPageProps {
  params: {
    findingId: string;
  };
}

export async function generateMetadata({ params }: FindingDetailPageProps): Promise<Metadata> {
  return {
    title: `Finding ${params.findingId} | Medusa Operations Console`
  };
}

export default async function FindingDetailPage({ params }: FindingDetailPageProps) {
  let error: string | null = null;

  const finding = await fetchFinding(params.findingId).catch((err) => {
    error = err instanceof Error ? err.message : 'Unable to load finding.';
    return null;
  });

  if (!finding) {
    if (error?.includes('404')) {
      notFound();
    }

    return (
      <section className="space-y-4">
        <Link href="/findings" className="text-sm">
          ← Back to findings
        </Link>
        <div className="card border-red-500/40 bg-red-950/40 p-4 text-sm text-red-200">
          {error ?? 'Finding not available.'}
        </div>
      </section>
    );
  }

  const scannerValue =
    typeof finding.metadata?.['scanner'] === 'string'
      ? (finding.metadata['scanner'] as string)
      : 'unknown';

  return (
    <section className="space-y-6">
      <Link href="/findings" className="text-sm">
        ← Back to findings
      </Link>

      <article className="card space-y-5 p-6">
        <header className="space-y-2">
          <p className="text-xs uppercase tracking-[0.3em] text-sky-400">Finding</p>
          <h2 className="text-2xl font-semibold text-white">{finding.title}</h2>
          <div className="flex flex-wrap items-center gap-3">
            <StatusBadge value={finding.severity} />
            <StatusBadge value={finding.status} />
            <span className="rounded-full bg-surface-muted/60 px-2.5 py-0.5 text-xs font-mono text-gray-300">
              Scanner {scannerValue} • Rule {finding.template_id}
            </span>
          </div>
        </header>

        <section className="grid gap-4 md:grid-cols-2">
          <div className="rounded-lg border border-surface-muted/50 bg-surface-muted/20 p-4">
            <h3 className="text-xs font-semibold uppercase tracking-wide text-gray-400">Timestamps</h3>
            <dl className="mt-2 space-y-1 text-sm text-gray-200">
              <div className="flex justify-between">
                <dt>Detected</dt>
                <dd className="font-mono text-gray-300">{finding.detected_at}</dd>
              </div>
              <div className="flex justify-between">
                <dt>Last Updated</dt>
                <dd className="font-mono text-gray-300">{finding.updated_at}</dd>
              </div>
            </dl>
          </div>
          <div className="rounded-lg border border-surface-muted/50 bg-surface-muted/20 p-4">
            <h3 className="text-xs font-semibold uppercase tracking-wide text-gray-400">Scan Context</h3>
            <dl className="mt-2 space-y-1 text-sm text-gray-200">
              <div className="flex justify-between">
                <dt>Scan ID</dt>
                <dd className="font-mono text-gray-300">{finding.scan_id}</dd>
              </div>
              <div className="flex justify-between">
                <dt>Evidence</dt>
                <dd className="max-w-xs text-right text-gray-300">
                  {finding.evidence ?? 'Evidence redacted or not supplied by scanner.'}
                </dd>
              </div>
            </dl>
          </div>
        </section>

        <section className="rounded-lg border border-surface-muted/50 bg-surface-muted/20 p-4">
          <h3 className="text-xs font-semibold uppercase tracking-wide text-gray-400">Remediation</h3>
          <p className="mt-2 text-sm text-gray-200">
            {finding.remediation ??
              'Remediation guidance will be attached here once enrichment agents generate analyst-approved actions.'}
          </p>
        </section>
      </article>
    </section>
  );
}
