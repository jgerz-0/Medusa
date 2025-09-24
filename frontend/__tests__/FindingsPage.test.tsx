import type { AnchorHTMLAttributes, ReactNode } from 'react';

jest.mock('react', () => {
  const actual = jest.requireActual('react');
  return {
    ...actual,
    Suspense: ({ fallback }: { fallback?: ReactNode }) => fallback ?? null
  };
});
import { render, screen } from '@testing-library/react';
import FindingsPage from '@/app/findings/page';
import { fetchFindings, fetchFindingsTimeline, fetchReportExports } from '@/lib/api';

jest.mock('next/link', () => ({
  __esModule: true,
  default: ({
    children,
    href,
    prefetch: _prefetch,
    ...anchorProps
  }: { children: ReactNode; href: string; prefetch?: boolean } & AnchorHTMLAttributes<HTMLAnchorElement>) => (
    <a href={href} {...anchorProps}>
      {children}
    </a>
  )
}));

jest.mock('@/lib/api', () => ({
  fetchFindings: jest.fn(),
  fetchFindingsTimeline: jest.fn(),
  fetchReportExports: jest.fn()
}));

describe('FindingsPage filter normalization', () => {
  const mockFetchFindings = fetchFindings as jest.MockedFunction<typeof fetchFindings>;
  const mockFetchFindingsTimeline = fetchFindingsTimeline as jest.MockedFunction<typeof fetchFindingsTimeline>;
  const mockFetchReportExports = fetchReportExports as jest.MockedFunction<typeof fetchReportExports>;

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('normalizes mixed-case severity, status, and scope filters', async () => {
    mockFetchFindings.mockResolvedValue({
      data: [],
      pagination: { page: 1, pageSize: 50, total: 0 }
    });
    mockFetchFindingsTimeline.mockResolvedValue([]);
    mockFetchReportExports.mockResolvedValue([]);

    const ui = await FindingsPage({
      searchParams: {
        severity: 'CrItIcAl',
        status: 'OpEn',
        scope: 'MiXeD'
      }
    });

    render(ui);

    const severitySelect = screen.getByLabelText(/severity/i) as HTMLSelectElement;
    expect(severitySelect.value).toBe('critical');

    const statusSelect = screen.getByLabelText(/^status$/i) as HTMLSelectElement;
    expect(statusSelect.value).toBe('open');

    const scopeSelect = screen.getByLabelText(/scope status/i) as HTMLSelectElement;
    expect(scopeSelect.value).toBe('mixed');
  });

  it('builds export URLs that respect active filters', async () => {
    mockFetchFindings.mockResolvedValue({
      data: [],
      pagination: { page: 1, pageSize: 50, total: 0 }
    });
    mockFetchFindingsTimeline.mockResolvedValue([]);
    mockFetchReportExports.mockResolvedValue([]);

    const searchParams = {
      scan: 'abc-123',
      severity: 'High',
      status: 'Open',
      scope: 'In_Scope',
      tag: 'triaged',
      assigned: 'analyst@example.com',
      from: '2024-01-01T08:00',
      to: '2024-01-05T20:00'
    } as const;

    const ui = await FindingsPage({
      searchParams
    });

    render(ui);

    const pdfLink = screen.getByRole('link', { name: /export pdf/i });
    const htmlLink = screen.getByRole('link', { name: /export html/i });

    const pdfUrl = new URL(pdfLink.getAttribute('href') ?? '', 'https://example.com');
    expect(pdfUrl.pathname).toBe('/api/reports/export');
    expect(pdfUrl.searchParams.get('format')).toBe('pdf');
    expect(pdfUrl.searchParams.get('scanId')).toBe(searchParams.scan);
    expect(pdfUrl.searchParams.get('severity')).toBe('high');
    expect(pdfUrl.searchParams.get('status')).toBe('open');
    expect(pdfUrl.searchParams.get('scope')).toBe('in_scope');
    expect(pdfUrl.searchParams.get('tag')).toBe(searchParams.tag);
    expect(pdfUrl.searchParams.get('assigned')).toBe(searchParams.assigned);
    expect(pdfUrl.searchParams.get('from')).toBe(searchParams.from);
    expect(pdfUrl.searchParams.get('to')).toBe(searchParams.to);

    const htmlUrl = new URL(htmlLink.getAttribute('href') ?? '', 'https://example.com');
    expect(htmlUrl.searchParams.get('format')).toBe('html');
    expect(htmlUrl.searchParams.get('scanId')).toBe(searchParams.scan);
  });
});
