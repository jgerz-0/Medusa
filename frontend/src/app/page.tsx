import Link from "next/link";
import { HeroPanel } from "@/ui/components/HeroPanel";

export default function HomePage() {
  return (
    <main className="flex min-h-screen flex-col items-center justify-center gap-6 bg-slate-950 p-6 text-slate-100">
      <HeroPanel
        title="Medusa Security Orchestrator"
        subtitle="Agentic automation for recon, scanning, enrichment, and reporting."
      >
        <p className="max-w-3xl text-center text-base text-slate-300">
          This UI coordinates scanning scopes, tracks nuclei coverage, and exposes deterministic
          findings enriched with CVE intelligence. Future iterations will surface worker health and
          Kubernetes orchestration state for rapid triage.
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
      </HeroPanel>
    </main>
  );
}
