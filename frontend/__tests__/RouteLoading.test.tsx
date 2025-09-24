import { render, screen, within } from '@testing-library/react';
import ScansLoading from '@/app/scans/loading';
import FindingsLoading from '@/app/findings/loading';

describe('Route loading states', () => {
  it('renders the scans table skeleton with accessible markup', () => {
    render(<ScansLoading />);

    const tableStatus = screen.getByRole('status', { name: /loading scans table/i });
    expect(tableStatus).toBeInTheDocument();

    const table = within(tableStatus).getByRole('table', { name: /scans/i });
    const columns = within(table).getAllByRole('columnheader');
    expect(columns).toHaveLength(6);

    const rows = within(table).getAllByRole('row');
    expect(rows).toHaveLength(1);

    const skeletonRows = table.querySelectorAll('tbody tr');
    expect(skeletonRows.length).toBeGreaterThan(0);
    expect(within(tableStatus).getAllByTestId('table-skeleton-line').length).toBeGreaterThan(0);
  });

  it('renders the findings table skeleton with accessible markup', () => {
    render(<FindingsLoading />);

    const filterSkeletons = screen.getAllByRole('status', { name: /loading findings filters/i });
    expect(filterSkeletons).toHaveLength(1);

    const tableStatus = screen.getByRole('status', { name: /loading findings table/i });
    expect(tableStatus).toBeInTheDocument();

    const table = within(tableStatus).getByRole('table', { name: /findings/i });
    const columns = within(table).getAllByRole('columnheader');
    expect(columns).toHaveLength(7);

    const rows = within(table).getAllByRole('row');
    expect(rows).toHaveLength(1);

    const skeletonRows = table.querySelectorAll('tbody tr');
    expect(skeletonRows.length).toBeGreaterThan(0);
    expect(within(tableStatus).getAllByTestId('table-skeleton-line').length).toBeGreaterThan(0);
  });
});
