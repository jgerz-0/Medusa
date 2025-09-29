import { render, screen } from '@testing-library/react';

import { UpdateStatusForm } from '../forms';

jest.mock('react-dom', () => {
  const actual = jest.requireActual('react-dom');

  return {
    ...actual,
    useFormState: jest.fn(() => [{ status: 'idle', message: null }, '/findings/update-status']),
    useFormStatus: jest.fn(() => ({ pending: false }))
  };
});

describe('UpdateStatusForm', () => {
  it('disables pending validation status to prevent manual regression', () => {
    render(
      <UpdateStatusForm
        findingId="finding-123"
        currentStatus="pending_validation"
      />
    );

    const pendingOption = screen.getByRole('option', { name: 'Pending Validation' }) as HTMLOptionElement;
    const invalidatedOption = screen.getByRole('option', { name: 'Invalidated' }) as HTMLOptionElement;

    expect(pendingOption.disabled).toBe(true);
    expect(invalidatedOption.disabled).toBe(false);
  });
});
