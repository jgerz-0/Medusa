import { scheduleScanAction } from '@/app/scans/actions';
import type { SupportedScanner } from '@/app/scans/actions';
import { ControllerValidationError, createScan } from '@/lib/api';

jest.mock('@/lib/api', () => {
  const actual = jest.requireActual('@/lib/api');
  return {
    ...actual,
    createScan: jest.fn()
  };
});

jest.mock('next/cache', () => ({
  revalidatePath: jest.fn()
}));

const { revalidatePath } = jest.requireMock('next/cache');

describe('scheduleScanAction', () => {
  beforeEach(() => {
    jest.resetAllMocks();
  });

  it('returns validation issues when required fields are missing', async () => {
    const result = await scheduleScanAction({
      targetId: '',
      scanner: 'nuclei',
      parameters: { profile: '' }
    });

    expect(result.ok).toBe(false);
    expect(result.issues).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ field: 'targetId' }),
        expect.objectContaining({ field: 'profile' })
      ])
    );
    expect(revalidatePath).not.toHaveBeenCalled();
    expect(createScan).not.toHaveBeenCalled();
  });

  it('rejects unsupported scanner values', async () => {
    const result = await scheduleScanAction({
      targetId: '1',
      scanner: 'burp' as unknown as SupportedScanner,
      parameters: {}
    });

    expect(result.ok).toBe(false);
    expect(result.issues).toEqual(
      expect.arrayContaining([expect.objectContaining({ field: 'scanner' })])
    );
    expect(createScan).not.toHaveBeenCalled();
  });

  it('surfaces controller validation errors', async () => {
    const validationError = new ControllerValidationError('Invalid payload', 422, [
      { field: 'profile', message: 'Unsupported profile' }
    ]);
    (createScan as jest.Mock).mockRejectedValue(validationError);

    const result = await scheduleScanAction({
      targetId: '42',
      scanner: 'nuclei',
      parameters: { profile: 'bad-profile' }
    });

    expect(result.ok).toBe(false);
    expect(result.message).toBe('Invalid payload');
    expect(result.issues).toEqual(validationError.issues);
    expect(revalidatePath).not.toHaveBeenCalled();
  });

  it('maps controller target validation to the target selector field', async () => {
    const validationError = new ControllerValidationError('Invalid payload', 422, [
      { field: 'target_id', message: 'Select an authorized target' }
    ]);
    (createScan as jest.Mock).mockRejectedValue(validationError);

    const result = await scheduleScanAction({
      targetId: 'invalid-target',
      scanner: 'nuclei',
      parameters: { profile: 'web-baseline' }
    });

    expect(result.ok).toBe(false);
    expect(result.issues).toEqual(
      expect.arrayContaining([expect.objectContaining({ field: 'targetId' })])
    );
  });

  it('queues the scan and revalidates the listing on success', async () => {
    const now = new Date().toISOString();
    (createScan as jest.Mock).mockResolvedValue({
      id: 'scan-1',
      target_id: '7',
      target: 'https://app.medusa.local',
      scanner: 'nuclei',
      status: 'queued',
      created_at: now,
      updated_at: now,
      initiated_by: 'analyst@example.com',
      findings_count: 0
    });

    const result = await scheduleScanAction({
      targetId: '7',
      scanner: 'nuclei',
      parameters: {
        profile: 'web-baseline',
        requested_hosts: ['www.medusa.local', ' www.medusa.local ', 'api.medusa.local']
      }
    });

    expect(createScan).toHaveBeenCalledWith({
      target_id: '7',
      scanner: 'nuclei',
      parameters: {
        profile: 'web-baseline',
        requested_hosts: ['www.medusa.local', 'api.medusa.local']
      }
    });
    expect(result.ok).toBe(true);
    expect(result.message).toContain('Scan queued');
    expect(revalidatePath).toHaveBeenCalledWith('/scans');
  });

  it('validates zap parameters against controller guardrails', async () => {
    const result = await scheduleScanAction({
      targetId: '1',
      targetScope: 'tcp://db.local',
      scanner: 'zap',
      parameters: { policy: 'invalid', mode: 'baseline', rate_limit: '0' }
    });

    expect(result.ok).toBe(false);
    expect(result.issues).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ field: 'targetId' }),
        expect.objectContaining({ field: 'policy' })
      ])
    );
  });

  it('coerces sqlmap parameters and enforces risk bounds', async () => {
    const result = await scheduleScanAction({
      targetId: '1',
      targetScope: 'https://app.local',
      scanner: 'sqlmap',
      parameters: { level: 3, risk: 7, request_delay: '0.250' }
    });

    expect(result.ok).toBe(false);
    expect(result.issues).toEqual(
      expect.arrayContaining([expect.objectContaining({ field: 'risk' })])
    );

    const now = new Date().toISOString();
    (createScan as jest.Mock).mockResolvedValueOnce({
      id: 'scan-sqlmap',
      target_id: '1',
      target: 'https://app.local',
      scanner: 'sqlmap',
      status: 'queued',
      created_at: now,
      updated_at: now,
      findings_count: 0
    });

    const success = await scheduleScanAction({
      targetId: '1',
      targetScope: 'https://app.local',
      scanner: 'sqlmap',
      parameters: { level: 3, risk: 1, request_delay: '0.250' }
    });

    expect(success.ok).toBe(true);
    expect(createScan).toHaveBeenLastCalledWith({
      target_id: '1',
      scanner: 'sqlmap',
      parameters: { level: 3, risk: 1, request_delay: '0.25' }
    });
  });
});
