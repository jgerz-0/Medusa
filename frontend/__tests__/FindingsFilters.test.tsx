import type { AnchorHTMLAttributes, ReactNode } from 'react';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { FindingsFilters } from '@/components/FindingsFilters';

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
});
