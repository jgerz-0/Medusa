import type { AnchorHTMLAttributes, ReactNode } from 'react';
import { render, screen, within } from '@testing-library/react';
import FindingDetailPage from '@/app/findings/[findingId]/page';
import { fetchFinding, fetchFindingComments, fetchFindingTimeline } from '@/lib/api';
import type { Finding, FindingComment, FindingTimelineEvent } from '@/lib/types';

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
  fetchFinding: jest.fn(),
  fetchFindingComments: jest.fn(),
  fetchFindingTimeline: jest.fn()
}));

describe('FindingDetailPage RBAC notice', () => {
  const mockFetchFinding = fetchFinding as jest.MockedFunction<typeof fetchFinding>;
  const mockFetchFindingComments = fetchFindingComments as jest.MockedFunction<
    typeof fetchFindingComments
  >;
  const mockFetchFindingTimeline = fetchFindingTimeline as jest.MockedFunction<
    typeof fetchFindingTimeline
  >;
  let consoleErrorSpy: jest.SpyInstance;

  const baseFinding: Finding = {
    id: 'finding-1',
    scan_id: 'scan-1',
    scanner: 'nuclei',
    sample_id: null,
    tool: null,
    category: 'web',
    title: 'Injected SQL parameter',
    description: 'Test finding.',
    severity: 'critical',
    status: 'open',
    template_id: 'CUST-001',
    detected_at: '2024-01-01T00:00:00.000Z',
    updated_at: '2024-01-01T01:00:00.000Z',
    evidence: 'Parameter id vulnerable to injection.',
    remediation: 'Apply parameterized queries.',
    enrichments: [],
    metadata: { scanner: 'nuclei' },
    assigned_to: 'analyst',
    tags: ['workflow:triage'],
    comment_count: 0,
    tickets: [],
    scope_status: 'in_scope'
  };

  beforeAll(() => {
    // Next.js server actions wire functions to form.action which React warns about in tests.
    consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterAll(() => {
    consoleErrorSpy.mockRestore();
  });

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('renders RequiredRolesNotice with workflow, ticket, and export scopes', async () => {
    mockFetchFinding.mockResolvedValue(baseFinding);
    mockFetchFindingComments.mockResolvedValue([] as FindingComment[]);
    mockFetchFindingTimeline.mockResolvedValue([] as FindingTimelineEvent[]);

    const ui = await FindingDetailPage({ params: { findingId: baseFinding.id } });

    render(ui);

    const notice = screen.getByRole('note', { name: /required rbac roles/i });
    const noticeContent = within(notice);

    expect(noticeContent.getByText('Execute workflow edits')).toBeInTheDocument();
    expect(noticeContent.getByText('analyst')).toBeInTheDocument();
    expect(noticeContent.getByText('Queue external tickets')).toBeInTheDocument();
    expect(noticeContent.getByText('ticket:create')).toBeInTheDocument();
    expect(noticeContent.getByText('Export formal reports')).toBeInTheDocument();
    expect(noticeContent.getByText('report:export')).toBeInTheDocument();
  });
});
