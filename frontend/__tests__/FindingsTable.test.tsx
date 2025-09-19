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
        description: 'TLS certificate expired',
        cve_id: null,
        severity: 'high',
        status: 'open',
        template_id: 'nuclei-tls-expired',
        detected_at: '2024-02-01T10:00:00Z',
        updated_at: '2024-02-01T11:30:00Z',
        evidence: 'certificate expired 12 hours ago',
        enrichments: [
          {
            id: 'enrichment-1',
            job_id: 'job-1',
            generated_at: '2024-02-01T09:55:00Z',
            recorded_at: '2024-02-01T09:55:10Z',
            advisories: [
              {
                source: 'nvd',
                identifier: 'CVE-2024-1111',
                references: [],
                raw: {}
              }
            ],
            advisories_hash: 'hash-a',
            errors: {},
            errors_hash: 'hash-b',
            provenance: { worker_subject: 'worker:enrichment' },
            provenance_hash: 'hash-c',
            payload_hash: 'hash-d'
          }
        ]
        ,
        metadata: { scanner: 'nuclei', rule_id: 'nuclei-tls-expired' }
      },
      {
        id: 'finding-002',
        scan_id: 'scan-001',
        title: 'Directory listing enabled',
        description: 'Directory listing enabled',
        cve_id: null,
        severity: 'medium',
        status: 'acknowledged',
        template_id: 'nuclei-dir-listing',
        detected_at: '2024-01-31T16:00:00Z',
        updated_at: '2024-01-31T18:00:00Z',
        enrichments: [],
        metadata: { scanner: 'nuclei', rule_id: 'nuclei-dir-listing' }
      }
    ];

    render(<FindingsTable findings={findings} />);

    expect(screen.getAllByTestId(/status-/i)).toHaveLength(4);
    expect(screen.getByText('TLS certificate expired')).toBeVisible();
    expect(screen.getByText('Directory listing enabled')).toBeVisible();
    expect(screen.getAllByText(/ago$/i)).toHaveLength(5);
    expect(screen.getByText('1 advisory')).toBeVisible();
    expect(screen.getByText('Not enriched')).toBeVisible();
  });

  it('renders scanner metadata for ZAP and SQLMap findings', () => {
    const findings: Finding[] = [
      {
        id: 'finding-zap',
        scan_id: 'scan-zap',
        title: 'Cross-site scripting',
        description: 'Reflected XSS detected',
        cve_id: 'CVE-2024-9999',
        severity: 'high',
        status: 'open',
        template_id: 'zap:40012',
        detected_at: '2024-02-01T08:00:00Z',
        updated_at: '2024-02-01T08:10:00Z',
        evidence: 'alert() payload reflected',
        enrichments: [],
        metadata: { scanner: 'zap', rule_id: 'zap:40012' }
      },
      {
        id: 'finding-sqlmap',
        scan_id: 'scan-sqlmap',
        title: 'Boolean-based SQLi',
        description: 'Time based injection',
        cve_id: null,
        severity: 'medium',
        status: 'open',
        template_id: 'sqlmap:id',
        detected_at: '2024-02-01T07:00:00Z',
        updated_at: '2024-02-01T07:05:00Z',
        evidence: null,
        enrichments: [],
        metadata: { scanner: 'sqlmap', rule_id: 'sqlmap:id' }
      }
    ];

    render(<FindingsTable findings={findings} />);

    expect(screen.getByText('Scanner zap • Rule zap:40012')).toBeVisible();
    expect(screen.getByText('Scanner sqlmap • Rule sqlmap:id')).toBeVisible();
  });
});
