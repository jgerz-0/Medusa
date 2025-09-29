import type { AnchorHTMLAttributes, ReactNode } from 'react';

jest.mock('react', () => {
  const actual = jest.requireActual('react');
  return {
    ...actual,
    Suspense: ({ fallback }: { fallback?: ReactNode }) => fallback ?? null
  };
});
import { render, screen, within } from '@testing-library/react';
import FindingsPage, { FindingsExportsBoundary } from '@/app/findings/page';
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
    mockFetchReportExports.mockResolvedValue({ data: [], pagination: null });

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
    mockFetchReportExports.mockResolvedValue({ data: [], pagination: null });

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

describe('Findings exports pagination', () => {
  const mockFetchReportExports = fetchReportExports as jest.MockedFunction<typeof fetchReportExports>;

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('preserves pagination state in export navigation links', async () => {
    mockFetchReportExports.mockResolvedValue({
      data: [
        {
          report_id: 'rep-1',
          format: 'pdf',
          generated_at: '2024-01-01T00:00:00.000Z',
          finding_count: 3,
          checksum: 'abc123',
          requested_by: 'analyst',
          storage: { bucket: 'reports', key: 'rep-1.pdf', content_type: 'application/pdf' },
          metadata: {}
        }
      ],
      pagination: { page: 2, pageSize: 10, total: 25 }
    });

    const ui = await FindingsExportsBoundary({
      scanId: 'scan-1',
      searchParams: { exports_page: '2', exports_page_size: '10' },
      basePath: '/findings'
    });

    render(ui);

    expect(mockFetchReportExports).toHaveBeenCalledWith({
      scanId: 'scan-1',
      page: 2,
      pageSize: 10
    });

    const exportsRegion = screen.getByRole('region', { name: /recent exports/i });
    const nextLink = within(exportsRegion).getByRole('link', { name: /next/i });
    expect(nextLink.getAttribute('href')).toContain('/findings');
    expect(nextLink.getAttribute('href')).toContain('exports_page=3');
    expect(nextLink.getAttribute('href')).toContain('exports_page_size=10');

    const prevLink = within(exportsRegion).getByRole('link', { name: /prev/i });
    expect(prevLink.getAttribute('href')).toContain('exports_page=1');
  });

  it('renders empty state messaging when paginated exports have no rows on current page', async () => {
    mockFetchReportExports.mockResolvedValue({
      data: [],
      pagination: { page: 3, pageSize: 5, total: 7 }
    });

    const ui = await FindingsExportsBoundary({
      scanId: 'scan-2',
      searchParams: { exports_page: '3', exports_page_size: '5' },
      basePath: '/findings'
    });

    render(ui);

    const exportsRegion = screen.getByRole('region', { name: /recent exports/i });
    expect(
      within(exportsRegion).getByText(/no exports available for this page/i)
    ).toBeInTheDocument();

    const statusRegion = within(exportsRegion).getByRole('status');
    expect(statusRegion).toHaveTextContent('Showing 6–7 of 7');
    expect(statusRegion).toHaveTextContent('Page 2 of 2');
  });
});
