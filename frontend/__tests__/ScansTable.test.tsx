import { render, screen, within } from '@testing-library/react';
import { ScansTable } from '@/components/ScansTable';
import type { Scan } from '@/lib/types';

describe('ScansTable', () => {
  const fixedDate = new Date('2024-01-01T00:00:00Z');

  beforeAll(() => {
    jest.useFakeTimers();
    jest.setSystemTime(fixedDate);
  });

  afterAll(() => {
    jest.useRealTimers();
  });

  it('renders deterministic scan rows with status badges', () => {
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

    const table = screen.getByRole('table');
    const rows = within(table).getAllByRole('row');
    // first row is header
    expect(rows).toHaveLength(scans.length + 1);

    expect(screen.getByTestId('status-running')).toBeVisible();
    expect(screen.getByTestId('status-completed')).toBeVisible();

    expect(screen.getAllByText(/ago$/i)).toHaveLength(4);
  });
});
