'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import clsx from 'clsx';
import { ReactNode } from 'react';

const navigation = [
  { name: 'Targets', href: '/targets' },
  { name: 'Discovery', href: '/discovery' },
  { name: 'Scans', href: '/scans' },
  { name: 'Findings', href: '/findings' }
];

export function LayoutShell({ children }: { children: ReactNode }) {
  const pathname = usePathname();

  return (
    <div className="min-h-screen">
      <header className="border-b border-surface-muted/70 bg-surface-default/80 backdrop-blur">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
          <div>
            <p className="text-xs uppercase tracking-[0.2em] text-sky-400">Medusa</p>
            <h1 className="text-xl font-semibold text-white">Operations Console</h1>
            <p className="text-xs text-gray-400">
              Security analysts monitor orchestrated scans, findings, and remediation queues here.
            </p>
          </div>
          <nav className="flex items-center gap-2">
            {navigation.map((item) => {
              const active = pathname.startsWith(item.href);
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  className={clsx(
                    'rounded-lg px-3 py-2 text-sm font-medium transition-colors',
                    active
                      ? 'bg-surface-muted text-white shadow-inner'
                      : 'text-gray-300 hover:text-white hover:bg-surface-muted/70'
                  )}
                >
                  {item.name}
                </Link>
              );
            })}
          </nav>
        </div>
      </header>
      <main className="mx-auto max-w-6xl px-6 py-8">
        <div className="space-y-6">{children}</div>
      </main>
    </div>
  );
}
