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
  it('only exposes controller-approved status transitions', () => {
    render(
      <UpdateStatusForm
        findingId="finding-123"
        currentStatus="pending_validation"
      />
    );

    const options = screen.getAllByRole('option') as HTMLOptionElement[];
    const readOnlyOption = screen.getByRole('option', { name: /Pending Validation/i }) as HTMLOptionElement;

    expect(readOnlyOption.disabled).toBe(true);
    expect(readOnlyOption.value).toBe('');

    const enabledStatuses = options
      .filter((option) => !option.disabled)
      .map((option) => option.value);

    expect(enabledStatuses).toEqual(['open', 'acknowledged', 'resolved']);
    expect(screen.queryByRole('option', { name: /Invalidated/i })).not.toBeInTheDocument();
  });
});
