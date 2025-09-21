import type { AnchorHTMLAttributes, ReactNode } from 'react';
import { render, screen } from '@testing-library/react';
import FindingsPage from '@/app/findings/page';
import { fetchFindings, fetchFindingsTimeline } from '@/lib/api';

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
  fetchFindingsTimeline: jest.fn()
}));

describe('FindingsPage filter normalization', () => {
  const mockFetchFindings = fetchFindings as jest.MockedFunction<typeof fetchFindings>;
  const mockFetchFindingsTimeline = fetchFindingsTimeline as jest.MockedFunction<typeof fetchFindingsTimeline>;

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('normalizes mixed-case severity, status, and scope filters', async () => {
    mockFetchFindings.mockResolvedValue({
      data: [],
      pagination: { page: 1, pageSize: 50, total: 0 }
    });
    mockFetchFindingsTimeline.mockResolvedValue([]);

    const ui = await FindingsPage({
      searchParams: {
        severity: 'CrItIcAl',
        status: 'OpEn',
        scope: 'MiXeD'
      }
    });

    render(ui);

    expect(mockFetchFindings).toHaveBeenCalledWith(
      expect.objectContaining({
        severity: 'critical',
        status: 'open',
        scope: 'mixed'
      })
    );
    expect(mockFetchFindingsTimeline).toHaveBeenCalledWith(
      expect.objectContaining({
        severity: 'critical',
        status: 'open',
        scope: 'mixed'
      })
    );

    const severitySelect = screen.getByLabelText(/severity/i) as HTMLSelectElement;
    expect(severitySelect.value).toBe('critical');

    const statusSelect = screen.getByLabelText(/^status$/i) as HTMLSelectElement;
    expect(statusSelect.value).toBe('open');

    const scopeSelect = screen.getByLabelText(/scope status/i) as HTMLSelectElement;
    expect(scopeSelect.value).toBe('mixed');
  });
});
