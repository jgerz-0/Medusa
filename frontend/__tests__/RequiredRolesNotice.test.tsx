import { render } from '@testing-library/react';
import { RequiredRolesNotice } from '@/components/RequiredRolesNotice';
import {
  ROLE_ANALYST,
  ROLE_FINDINGS_READ,
  ROLE_SCAN_ENQUEUE,
  ROLE_SCANS_READ,
  ROLE_TARGETS_READ
} from '@/lib/rbac';

describe('RequiredRolesNotice', () => {
  it('renders a deterministic RBAC summary for scan and finding workflows', () => {
    const { container } = render(
      <RequiredRolesNotice
        sections={[
          {
            title: 'View scan inventory',
            description: 'Lists queued, running, and completed jobs for authorized scopes.',
            roles: [ROLE_SCANS_READ]
          },
          {
            title: 'Load target catalog',
            description: 'Populates the launch form with registered, in-scope assets.',
            roles: [ROLE_TARGETS_READ]
          },
          {
            title: 'Launch scans',
            description: 'Allows dispatching nuclei, ZAP, or SQLMap jobs to workers.',
            roles: [ROLE_SCAN_ENQUEUE]
          },
          {
            title: 'Triage findings',
            description: 'Enables acknowledgement, assignment, and tagging workflows.',
            roles: [ROLE_FINDINGS_READ, ROLE_ANALYST]
          }
        ]}
      />
    );

    expect(container.firstChild).toMatchSnapshot();
  });
});
