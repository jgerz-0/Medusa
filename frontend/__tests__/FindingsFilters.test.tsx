import type { AnchorHTMLAttributes, ReactNode } from 'react';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { FindingsFilters } from '@/components/FindingsFilters';
import { FINDING_STATUSES } from '@/lib/types';

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

describe('FindingsFilters scope control', () => {
  it('renders every supported finding status option with normalized labels', () => {
    render(<FindingsFilters />);

    const statusSelect = screen.getByLabelText(/^status$/i) as HTMLSelectElement;

    const optionEntries = Array.from(statusSelect.options).map((option) => ({
      value: option.value,
      label: option.text,
    }));

    const expected = [
      { value: '', label: 'Any' },
      ...FINDING_STATUSES.map((status) => ({
        value: status,
        label: status
          .split('_')
          .map((segment) => segment.charAt(0).toUpperCase() + segment.slice(1))
          .join(' '),
      })),
    ];

    expect(optionEntries).toEqual(expected);
  });

  it('submits the selected scope option as a query parameter', async () => {
    expect.assertions(3);

    render(<FindingsFilters />);

    const scopeSelect = screen.getByLabelText(/scope status/i) as HTMLSelectElement;
    const form = scopeSelect.closest('form') as HTMLFormElement;

    const submitHandler = jest.fn((event: Event) => {
      event.preventDefault();

      const formData = new FormData(form);
      const params = new URLSearchParams();
      formData.forEach((value, key) => {
        if (typeof value === 'string') {
          params.append(key, value);
        }
      });

      expect(params.get('scope')).toBe('mixed');
      expect(params.toString()).toContain('scope=mixed');
    });

    form.addEventListener('submit', submitHandler as EventListener);

    const user = userEvent.setup();
    await user.selectOptions(scopeSelect, 'mixed');
    await user.click(screen.getByRole('button', { name: /apply/i }));

    expect(submitHandler).toHaveBeenCalledTimes(1);

    form.removeEventListener('submit', submitHandler as EventListener);
  });

  it('formats controller timestamps for datetime-local inputs', () => {
    render(
      <FindingsFilters
        searchParams={{
          from: '2024-04-01T12:30:45.000Z',
          to: '2024-04-02T08:09:10+02:00',
        }}
      />,
    );

    const fromInput = screen.getByLabelText(/from/i) as HTMLInputElement;
    const toInput = screen.getByLabelText(/^to$/i) as HTMLInputElement;

    expect(fromInput.value).toBe('2024-04-01T12:30');
    expect(toInput.value).toBe('2024-04-02T08:09');
  });
});
