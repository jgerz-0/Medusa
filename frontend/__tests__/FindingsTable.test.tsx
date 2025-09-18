import { render, screen } from '@testing-library/react';
import { FindingsTable } from '@/components/FindingsTable';
import type { Finding } from '@/lib/types';

describe('FindingsTable', () => {
  const fixedDate = new Date('2024-02-01T12:00:00Z');

  beforeAll(() => {
    jest.useFakeTimers();
    jest.setSystemTime(fixedDate);
  });

  afterAll(() => {
    jest.useRealTimers();
  });

  it('renders severity and status badges for deterministic findings', () => {
    const findings: Finding[] = [
      {
        id: 'finding-001',
        scan_id: 'scan-001',
        title: 'TLS certificate expired',
        severity: 'high',
        status: 'open',
        template_id: 'nuclei-tls-expired',
        detected_at: '2024-02-01T10:00:00Z',
        updated_at: '2024-02-01T11:30:00Z',
        evidence: 'certificate expired 12 hours ago'
      },
      {
        id: 'finding-002',
        scan_id: 'scan-001',
        title: 'Directory listing enabled',
        severity: 'medium',
        status: 'acknowledged',
        template_id: 'nuclei-dir-listing',
        detected_at: '2024-01-31T16:00:00Z',
        updated_at: '2024-01-31T18:00:00Z'
      }
    ];

    render(<FindingsTable findings={findings} />);

    expect(screen.getAllByTestId(/status-/i)).toHaveLength(4);
    expect(screen.getByText('TLS certificate expired')).toBeVisible();
    expect(screen.getByText('Directory listing enabled')).toBeVisible();
    expect(screen.getAllByText(/ago$/i)).toHaveLength(4);
  });
});
