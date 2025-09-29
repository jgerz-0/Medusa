import { render, screen } from '@testing-library/react';

import { StatusBadge } from '@/components/StatusBadge';
import { FINDING_STATUSES } from '@/lib/types';

describe('StatusBadge', () => {
  it.each(FINDING_STATUSES)('renders finding status %s without errors', (status) => {
    render(<StatusBadge value={status} />);

    const badge = screen.getByTestId(`status-${status}`);
    expect(badge).toHaveTextContent(status);
  });

  it('renders invalidated findings with dedicated styling token', () => {
    render(<StatusBadge value="invalidated" />);

    const badge = screen.getByTestId('status-invalidated');
    expect(badge.className).toContain('status-invalidated');
  });
});
