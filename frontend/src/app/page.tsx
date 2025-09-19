import Link from "next/link";

export default function HomePage() {
  return (
    <main className="flex min-h-screen flex-col items-center justify-center gap-6 bg-slate-950 p-6 text-slate-100">
      <section className="w-full max-w-4xl space-y-5 rounded-2xl border border-slate-800 bg-slate-900/50 p-8 text-center shadow-lg">
        <header className="space-y-2">
          <p className="text-xs uppercase tracking-[0.4em] text-emerald-400">Medusa</p>
          <h1 className="text-3xl font-semibold text-slate-50">Medusa Security Orchestrator</h1>
          <p className="text-base text-slate-300">
            Agentic automation for recon, scanning, enrichment, and reporting.
          </p>
        </header>
        <p className="mx-auto max-w-3xl text-sm text-slate-300">
          This console coordinates scanning scopes, tracks nuclei coverage, and exposes deterministic findings enriched
          with CVE intelligence. Future iterations will surface worker health and Kubernetes orchestration state for
          rapid triage.
        </p>
        <div className="flex flex-wrap items-center justify-center gap-4">
          <Link
            className="rounded bg-emerald-500 px-4 py-2 text-sm font-semibold text-slate-950 shadow hover:bg-emerald-400"
            href="/scopes"
          >
            Manage Scopes
          </Link>
          <Link
            className="rounded border border-slate-600 px-4 py-2 text-sm font-semibold text-slate-100 hover:border-emerald-400 hover:text-emerald-300"
            href="/reports"
          >
            Review Reports
          </Link>
        </div>
      </section>
    </main>
  );
}
