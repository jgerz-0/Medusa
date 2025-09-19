import { render, screen, waitFor } from '@testing-library/react';
import { act } from 'react-dom/test-utils';
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
      scope: 'https://app.medusa.local',
      is_authorized: true,
      created_at: '2024-01-01T00:00:00Z',
      updated_at: '2024-01-01T00:00:00Z'
    },
    {
      id: '2',
      name: 'Legacy Portal',
      scope: 'https://portal.medusa.local',
      is_authorized: false,
      created_at: '2024-01-01T00:00:00Z',
      updated_at: '2024-01-01T00:00:00Z'
    },
    {
      id: '3',
      name: 'Internal Database',
      scope: 'tcp://db.medusa.local',
      is_authorized: true,
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

    await act(async () => {
      await user.click(screen.getByRole('button', { name: /queue scan/i }));
    });

    expect(
      screen.getByText('Select a target within the authorized scope before launching a scan.')
    ).toBeInTheDocument();
    expect(mockedScheduleScanAction).not.toHaveBeenCalled();
  });

  it('queues a scan and surfaces the success message', async () => {
    const user = userEvent.setup();
    mockedScheduleScanAction.mockResolvedValue({
      ok: true,
      message: 'Scan queued for app.medusa.local'
    });

    render(<ScanLaunchForm targets={targets} />);

    await act(async () => {
      await user.selectOptions(screen.getByLabelText('Target'), '1');
      await user.click(screen.getByRole('button', { name: /queue scan/i }));
    });

    expect(mockedScheduleScanAction).toHaveBeenCalledWith({
      targetId: '1',
      targetScope: targets[0].scope,
      scanner: 'nuclei',
      parameters: expect.objectContaining({ profile: scanPresets[0].profile })
    });

    await waitFor(() => {
      expect(screen.getByText(/Scan queued for app\.medusa\.local/)).toBeVisible();
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

    await act(async () => {
      await user.selectOptions(screen.getByLabelText('Target'), '1');
      await user.selectOptions(screen.getByLabelText('Nuclei Profile'), scanPresets[1].id);
      await user.click(screen.getByRole('button', { name: /queue scan/i }));
    });

    await waitFor(() => {
      expect(screen.getByText(/Controller rejected the payload/)).toBeVisible();
    });
    expect(screen.getByText(/profile: Unsupported profile/)).toBeVisible();
  });

  it('queues a zap scan with tuned parameters', async () => {
    const user = userEvent.setup();
    mockedScheduleScanAction.mockResolvedValue({ ok: true, message: 'ZAP scan queued' });

    render(<ScanLaunchForm targets={targets} />);

    await act(async () => {
      await user.selectOptions(screen.getByLabelText('Target'), '1');
      await user.selectOptions(screen.getByLabelText('Scanner'), 'OWASP ZAP (passive or active web scan)');
      await user.selectOptions(screen.getByLabelText('ZAP Policy'), 'Full Active');
      await user.selectOptions(screen.getByLabelText('ZAP Mode'), 'Full Mode');

      const rateLimitInput = screen.getByLabelText(/Rate Limit/);
      await user.clear(rateLimitInput);
      await user.type(rateLimitInput, '2');

      await user.click(screen.getByRole('button', { name: /queue scan/i }));
    });

    await waitFor(() => {
      expect(mockedScheduleScanAction).toHaveBeenLastCalledWith({
        targetId: '1',
        targetScope: targets[0].scope,
        scanner: 'zap',
        parameters: { policy: 'full', mode: 'full', rate_limit: '2' }
      });
    });
  });

  it('surfaces zap policy validation errors inline', async () => {
    const user = userEvent.setup();
    mockedScheduleScanAction.mockResolvedValue({
      ok: false,
      message: 'Fix ZAP policy',
      issues: [{ field: 'policy', message: 'ZAP policy must be baseline or full.' }]
    });

    render(<ScanLaunchForm targets={targets} />);

    await act(async () => {
      await user.selectOptions(screen.getByLabelText('Target'), '1');
      await user.selectOptions(screen.getByLabelText('Scanner'), 'OWASP ZAP (passive or active web scan)');
      await user.click(screen.getByRole('button', { name: /queue scan/i }));
    });

    await waitFor(() => {
      expect(screen.getByText(/Fix ZAP policy/)).toBeVisible();
    });
    expect(screen.getByText('ZAP policy must be baseline or full.')).toBeVisible();
  });

  it('queues a sqlmap scan with throttling controls', async () => {
    const user = userEvent.setup();
    mockedScheduleScanAction.mockResolvedValue({ ok: true, message: 'SQLMap scan queued' });

    render(<ScanLaunchForm targets={targets} />);

    await act(async () => {
      await user.selectOptions(screen.getByLabelText('Target'), '1');
      await user.selectOptions(screen.getByLabelText('Scanner'), 'SQLMap (injection validation)');
      await user.selectOptions(screen.getByLabelText('SQLMap Level'), 'Level 5');
      await user.selectOptions(screen.getByLabelText('SQLMap Risk'), 'Risk 3');

      const delayInput = screen.getByLabelText(/Request Delay/);
      await user.clear(delayInput);
      await user.type(delayInput, '0.5');

      await user.click(screen.getByRole('button', { name: /queue scan/i }));
    });

    await waitFor(() => {
      expect(mockedScheduleScanAction).toHaveBeenLastCalledWith({
        targetId: '1',
        targetScope: targets[0].scope,
        scanner: 'sqlmap',
        parameters: { level: 5, risk: 3, request_delay: '0.5' }
      });
    });
  });

  it('warns when selecting zap for a non-http target', async () => {
    const user = userEvent.setup();
    render(<ScanLaunchForm targets={targets} />);

    await act(async () => {
      await user.selectOptions(screen.getByLabelText('Target'), '3');
      await user.selectOptions(screen.getByLabelText('Scanner'), 'OWASP ZAP (passive or active web scan)');
    });

    expect(
      screen.getByText('ZAP and SQLMap require an HTTP or HTTPS scope. Select an HTTP(S) target to continue.')
    ).toBeVisible();
  });
});
