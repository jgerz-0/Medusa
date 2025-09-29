import type { AnchorHTMLAttributes, ReactNode } from 'react';
import { render, screen, within } from '@testing-library/react';
import FindingDetailPage from '@/app/findings/[findingId]/page';
import { fetchFinding, fetchFindingComments, fetchFindingTimeline, fetchReportExports } from '@/lib/api';
import type { Finding, FindingComment, FindingTimelineEvent } from '@/lib/types';

jest.mock('@/app/findings/[findingId]/forms', () => ({
  AssignFindingForm: ({ children }: { children?: ReactNode }) => (
    <div data-testid="assign-form">{children}</div>
  ),
  UpdateStatusForm: () => <div data-testid="update-status-form" />, 
  UpdateTagsForm: () => <div data-testid="update-tags-form" />, 
  CreateCommentForm: () => <div data-testid="create-comment-form" />, 
  CreateJiraTicketForm: () => <div data-testid="create-jira-ticket-form" />, 
  CreateGitHubTicketForm: () => <div data-testid="create-github-ticket-form" /> 
}));

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
  fetchFindingTimeline: jest.fn(),
  fetchReportExports: jest.fn()
}));

describe('FindingDetailPage RBAC notice', () => {
  const mockFetchFinding = fetchFinding as jest.MockedFunction<typeof fetchFinding>;
  const mockFetchFindingComments = fetchFindingComments as jest.MockedFunction<
    typeof fetchFindingComments
  >;
  const mockFetchFindingTimeline = fetchFindingTimeline as jest.MockedFunction<
    typeof fetchFindingTimeline
  >;
  const mockFetchReportExports = fetchReportExports as jest.MockedFunction<typeof fetchReportExports>;
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
    validation_status: 'pending',
    validated_at: null,
    validations: [],
    cvss: 9.5,
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
    jest.useRealTimers();
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it('renders RequiredRolesNotice with workflow, ticket, and export scopes', async () => {
    mockFetchFinding.mockResolvedValue(baseFinding);
    mockFetchFindingComments.mockResolvedValue([] as FindingComment[]);
    mockFetchFindingTimeline.mockResolvedValue([] as FindingTimelineEvent[]);
    mockFetchReportExports.mockResolvedValue({ data: [], pagination: null });

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

  it('renders ticket status badges and hyperlinks when available', async () => {
    jest.useFakeTimers();
    jest.setSystemTime(new Date('2024-01-01T05:00:00.000Z'));

    mockFetchReportExports.mockResolvedValue({ data: [], pagination: null });

    const findingWithTickets: Finding = {
      ...baseFinding,
      tickets: [
        {
          id: 'ticket-1',
          integration: 'jira',
          reference: 'JIRA-123',
          status: 'queued',
          url: 'https://jira.example.com/browse/JIRA-123',
          created_at: '2024-01-01T02:00:00.000Z',
          updated_at: '2024-01-01T02:10:00.000Z',
          synced_at: '2024-01-01T02:30:00.000Z',
          sync_error: null,
          metadata: {
            status_category: 'In Progress',
            assignee: 'analyst.one',
          }
        },
        {
          id: 'ticket-2',
          integration: 'github',
          reference: 'GH-1',
          status: 'acknowledged',
          url: null,
          created_at: '2024-01-01T03:00:00.000Z',
          updated_at: '2024-01-01T03:05:00.000Z',
          synced_at: null,
          sync_error: 'rate limited',
          metadata: {}
        },
      ]
    };

    mockFetchFinding.mockResolvedValue(findingWithTickets);
    mockFetchFindingComments.mockResolvedValue([] as FindingComment[]);
    mockFetchFindingTimeline.mockResolvedValue([] as FindingTimelineEvent[]);
    mockFetchReportExports.mockResolvedValue({ data: [], pagination: null });

    const ui = await FindingDetailPage({ params: { findingId: findingWithTickets.id } });

    render(ui);

    const jiraLink = screen.getByRole('link', { name: 'jira:JIRA-123' });
    expect(jiraLink).toHaveAttribute('href', 'https://jira.example.com/browse/JIRA-123');
    expect(screen.getByTestId('status-queued')).toBeInTheDocument();
    expect(
      screen.getByText((content) => content.startsWith('Synced') && content.includes('ago'))
    ).toBeInTheDocument();
    expect(screen.getAllByText('Stale')).toHaveLength(2);
    expect(screen.getByText('Status Category')).toBeInTheDocument();
    expect(screen.getByText('In Progress')).toBeInTheDocument();

    expect(screen.getByText('github:GH-1')).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'github:GH-1' })).not.toBeInTheDocument();
    expect(screen.getByTestId('status-acknowledged')).toBeInTheDocument();
    expect(screen.getByText('Awaiting first sync')).toBeInTheDocument();
    expect(screen.getByText('Sync Error')).toHaveAttribute('title', 'rate limited');

    jest.useRealTimers();
  });

  it('summarizes validation workflow details and surfaces the cvss score', async () => {
    jest.useFakeTimers();
    jest.setSystemTime(new Date('2024-01-03T00:00:00.000Z'));

    const findingWithValidation: Finding = {
      ...baseFinding,
      validation_status: 'passed',
      validated_at: '2024-01-02T12:00:00.000Z',
      validations: [
        {
          id: 'validation-1',
          job_id: 'job-001',
          status: 'passed',
          validator: 'validator.one',
          executed_at: '2024-01-02T12:00:00.000Z',
          requested_by: 'analyst',
          requested_at: '2024-01-02T11:00:00.000Z',
          notes: 'SQL injection blocked in WAF.',
          metadata: {},
          evidence: {}
        },
        {
          id: 'validation-0',
          job_id: 'job-000',
          status: 'failed',
          validator: 'validator.one',
          executed_at: '2024-01-01T12:00:00.000Z',
          requested_by: 'analyst',
          requested_at: '2024-01-01T11:00:00.000Z',
          notes: null,
          metadata: {},
          evidence: {}
        }
      ]
    };

    mockFetchFinding.mockResolvedValue(findingWithValidation);
    mockFetchFindingComments.mockResolvedValue([] as FindingComment[]);
    mockFetchFindingTimeline.mockResolvedValue([] as FindingTimelineEvent[]);
    mockFetchReportExports.mockResolvedValue({ data: [], pagination: null });

    const ui = await FindingDetailPage({ params: { findingId: findingWithValidation.id } });

    render(ui);

    const cvssBadge = screen.getByText('CVSS').closest('span');
    expect(cvssBadge).toHaveTextContent('CVSS9.5');
    expect(screen.getAllByTestId('status-passed').length).toBeGreaterThan(0);
    const latestRunTimes = screen.getAllByTitle('2024-01-02T12:00:00.000Z');
    expect(latestRunTimes.length).toBeGreaterThan(0);
    expect(screen.getByTitle('2024-01-01T12:00:00.000Z')).toBeInTheDocument();
    expect(screen.getByText('SQL injection blocked in WAF.')).toBeInTheDocument();
    expect(screen.getByText('No analyst notes recorded.')).toBeInTheDocument();

    jest.useRealTimers();
  });
});
