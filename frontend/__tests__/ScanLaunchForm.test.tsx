import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { ScanLaunchForm, scanPresets } from '@/components/ScanLaunchForm';
import { scheduleScanAction } from '@/app/scans/actions';
import type { Target } from '@/lib/types';

jest.mock('@/app/scans/actions', () => ({
  scheduleScanAction: jest.fn()
}));

const mockedScheduleScanAction = scheduleScanAction as jest.MockedFunction<typeof scheduleScanAction>;

describe('ScanLaunchForm', () => {
  const targets: Target[] = [
    {
      id: '1',
      name: 'App Cluster',
      url: 'https://app.medusa.local',
      scope: { allowed_hosts: ['app.medusa.local'] },
      is_authorized: true,
      created_at: '2024-01-01T00:00:00Z',
      updated_at: '2024-01-01T00:00:00Z'
    },
    {
      id: '2',
      name: 'Legacy Portal',
      url: 'https://portal.medusa.local',
      scope: { allowed_hosts: ['portal.medusa.local'] },
      is_authorized: false,
      created_at: '2024-01-01T00:00:00Z',
      updated_at: '2024-01-01T00:00:00Z'
    }
  ];

  beforeEach(() => {
    jest.resetAllMocks();
  });

  it('requires a target to be selected before submission', async () => {
    const user = userEvent.setup();
    render(<ScanLaunchForm targets={targets} />);

    await user.click(screen.getByRole('button', { name: /queue scan/i }));

    expect(
      screen.getByText('Select a target within the authorized scope before launching a scan.')
    ).toBeInTheDocument();
    expect(mockedScheduleScanAction).not.toHaveBeenCalled();
  });

  it('queues a scan and surfaces the success message', async () => {
    const user = userEvent.setup();
    mockedScheduleScanAction.mockResolvedValue({
      ok: true,
      message: 'Scan queued for https://app.medusa.local'
    });

    render(<ScanLaunchForm targets={targets} />);

    await user.selectOptions(screen.getByLabelText('Target'), '1');
    await user.click(screen.getByRole('button', { name: /queue scan/i }));

    expect(mockedScheduleScanAction).toHaveBeenCalledWith({
      targetId: '1',
      profile: scanPresets[0].profile,
      requestedHosts: scanPresets[0].requestedHosts
    });

    await waitFor(() => {
      expect(screen.getByText(/Scan queued for https:\/\/app.medusa.local/)).toBeVisible();
    });
  });

  it('renders validation errors returned by the server action', async () => {
    const user = userEvent.setup();
    mockedScheduleScanAction.mockResolvedValue({
      ok: false,
      message: 'Controller rejected the payload. Review validation errors.',
      issues: [{ field: 'profile', message: 'Unsupported profile' }]
    });

    render(<ScanLaunchForm targets={targets} />);

    await user.selectOptions(screen.getByLabelText('Target'), '1');
    await user.selectOptions(screen.getByLabelText('Scan Profile'), scanPresets[1].id);
    await user.click(screen.getByRole('button', { name: /queue scan/i }));

    await waitFor(() => {
      expect(screen.getByText(/Controller rejected the payload/)).toBeVisible();
    });
    expect(screen.getByText(/profile: Unsupported profile/)).toBeVisible();
  });
});
