import { ReactNode } from "react";

export type HeroPanelProps = {
  readonly title: string;
  readonly subtitle?: string;
  readonly children?: ReactNode;
};

/**
 * Presentational shell for key call-to-action sections in the Medusa portal.
 * Clear hierarchy ensures analysts can rapidly differentiate scope actions.
 */
export function HeroPanel({ title, subtitle, children }: HeroPanelProps) {
  return (
    <section className="flex w-full max-w-4xl flex-col items-center gap-4 rounded-2xl border border-slate-800 bg-slate-900/60 p-8 shadow-xl">
      <header className="flex flex-col items-center gap-2 text-center">
        <h1 className="text-3xl font-bold text-emerald-400">{title}</h1>
        {subtitle ? <p className="text-base text-slate-300">{subtitle}</p> : null}
      </header>
      {children}
    </section>
  );
}
