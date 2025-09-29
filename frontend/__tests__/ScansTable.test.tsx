import { render, screen, within } from '@testing-library/react';
import { ScansTable } from '@/components/ScansTable';
import { fetchScans } from '@/lib/api';
import type { Scan } from '@/lib/types';

jest.mock('next/headers', () => ({
  cookies: jest.fn(() => ({
    get: jest.fn()
  })),
  headers: jest.fn(() => new Headers())
}));

jest.mock('@/lib/auth', () => ({
  readSession: jest.fn().mockResolvedValue(null)
}));

describe('ScansTable', () => {
  const fixedDate = new Date('2024-01-01T00:00:00Z');

  beforeAll(() => {
    jest.useFakeTimers();
    jest.setSystemTime(fixedDate);
  });

  afterAll(() => {
    jest.useRealTimers();
  });

  it('renders deterministic scan rows with status badges and RBAC badges', () => {
    const scans: Scan[] = [
      {
        id: 'scan-001',
        target_id: 'target-001',
        target: 'https://app-1.medusa.local',
        scanner: 'nuclei',
        status: 'running',
        initiated_by: 'analyst@example.com',
        created_at: '2023-12-31T23:50:00Z',
        updated_at: '2023-12-31T23:59:00Z',
        findings_count: 3
      },
      {
        id: 'scan-002',
        target_id: 'target-002',
        target: 'https://api-1.medusa.local',
        scanner: 'nuclei',
        status: 'completed',
        created_at: '2023-12-30T11:00:00Z',
        updated_at: '2023-12-30T11:30:00Z',
        findings_count: 0
      }
    ];

    render(<ScansTable scans={scans} />);

    expect(screen.getByText('https://app-1.medusa.local')).toBeInTheDocument();
    expect(screen.getByText('https://api-1.medusa.local')).toBeInTheDocument();
    expect(screen.getByText('Scanner')).toBeInTheDocument();

    const scannerCells = screen.getAllByText('nuclei');
    expect(scannerCells).toHaveLength(2);

    const table = screen.getByRole('table', { name: /scans/i });
    const rows = within(table).getAllByRole('row');
    // first row is header
    expect(rows).toHaveLength(scans.length + 1);

    expect(screen.getByTestId('status-running')).toBeVisible();
    expect(screen.getByTestId('status-completed')).toBeVisible();

    expect(screen.getAllByText(/ago$/i)).toHaveLength(4);

    const rbacLabel = screen.getByText(/controller rbac/i);
    expect(rbacLabel).toBeInTheDocument();
    expect(screen.getByText('scans:read')).toBeInTheDocument();
  });

  it('advances pagination using page parameters while requesting limit/offset from the API', async () => {
    const scans: Scan[] = [];
    const pagination = { page: 1, pageSize: 25, total: 80 };

    render(
      <ScansTable
        scans={scans}
        pagination={pagination}
        searchParams={{}}
        basePath="/scans"
      />
    );

    const nextLink = screen.getByRole('link', { name: /next/i });
    const href = nextLink.getAttribute('href');
    expect(href).toContain('page=2');
    expect(href).toContain('page_size=25');

    const parsed = new URL(href ?? '', 'https://medusa.local');
    const nextPage = Number(parsed.searchParams.get('page'));
    const nextPageSize = Number(parsed.searchParams.get('page_size'));

    const originalFetch = globalThis.fetch;
    const fetchMock = jest.fn(async () => ({
      ok: true,
      status: 200,
      headers: {
        get: (name: string) => (name.toLowerCase() === 'content-type' ? 'application/json' : null)
      } as unknown as Headers,
      json: async () => ({ data: [], meta: { total: 0, limit: 25, offset: 25 } })
    }));
    // @ts-expect-error - override fetch for deterministic inspection in tests
    globalThis.fetch = fetchMock;

    try {
      await fetchScans({ page: nextPage, pageSize: nextPageSize });

      expect(fetchMock).toHaveBeenCalledTimes(1);
      const [requestUrl] = fetchMock.mock.calls[0] as [string];
      expect(requestUrl).toContain('limit=25');
      expect(requestUrl).toContain('offset=25');
    } finally {
      if (originalFetch) {
        globalThis.fetch = originalFetch;
      } else {
        delete (globalThis as Record<string, unknown>).fetch;
      }
    }
  });
});
