import { render, screen, within } from '@testing-library/react';

import type { FindingsTimelineBucket } from '@/lib/types';
import { FindingsTimeline } from '../FindingsTimeline';

describe('FindingsTimeline', () => {
  const buckets: FindingsTimelineBucket[] = [
    {
      date: '2024-05-01T12:00:00.000Z',
      open: 3,
      pending_validation: 0,
      acknowledged: 1,
      invalidated: 2,
      resolved: 4,
      total: 10
    },
    {
      date: '2024-05-02T12:00:00.000Z',
      open: 1,
      pending_validation: 1,
      acknowledged: 0,
      invalidated: 0,
      resolved: 1,
      total: 3
    }
  ];

  it('renders validation workflow columns and preserves zero counts', () => {
    render(<FindingsTimeline buckets={buckets} />);

    expect(screen.getByText(/validation workflow/i)).toBeInTheDocument();
    expect(screen.getByRole('columnheader', { name: /pending validation/i })).toBeInTheDocument();
    expect(screen.getByRole('columnheader', { name: /invalidated/i })).toBeInTheDocument();

    const firstDateLabel = new Date(buckets[0].date).toLocaleDateString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric'
    });
    const firstRow = screen.getByText(firstDateLabel).closest('tr');
    expect(firstRow).not.toBeNull();
    const firstRowCells = within(firstRow as HTMLTableRowElement).getAllByRole('cell');
    expect(firstRowCells[2]).toHaveTextContent('0');
    expect(firstRowCells[4]).toHaveTextContent('2');

    const secondDateLabel = new Date(buckets[1].date).toLocaleDateString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric'
    });
    const secondRow = screen.getByText(secondDateLabel).closest('tr');
    expect(secondRow).not.toBeNull();
    const secondRowCells = within(secondRow as HTMLTableRowElement).getAllByRole('cell');
    expect(secondRowCells[4]).toHaveTextContent('0');
  });
});
