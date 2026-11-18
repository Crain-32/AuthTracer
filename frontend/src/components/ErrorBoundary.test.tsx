import { render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { ErrorBoundary } from './ErrorBoundary';

function Part({ broken }: { broken: boolean }) {
  if (broken) {
    throw new Error('Unknown node type: widget');
  }
  return <p>Drawn</p>;
}

// React reports every error a boundary catches on the console.
beforeEach(() => vi.spyOn(console, 'error').mockImplementation(() => {}));
afterEach(() => vi.restoreAllMocks());

describe('ErrorBoundary', () => {
  it('shows its part as long as nothing breaks', () => {
    const { rerender } = render(<ErrorBoundary resetKeys={['paths']}><Part broken={false} /></ErrorBoundary>);
    rerender(<ErrorBoundary resetKeys={['lineage']}><Part broken={false} /></ErrorBoundary>);
    expect(screen.getByText('Drawn')).toBeInTheDocument();
  });

  it('shows what broke in place of its part, and tries again only when a reset key changes', () => {
    const { rerender } = render(<ErrorBoundary resetKeys={['paths', 1]}><Part broken /></ErrorBoundary>);
    expect(screen.getByRole('heading', { name: 'This part of the graph couldn\'t be shown' })).toBeInTheDocument();
    expect(screen.getByText('Unknown node type: widget')).toBeInTheDocument();
    rerender(<ErrorBoundary resetKeys={['paths', 1]}><Part broken={false} /></ErrorBoundary>);
    expect(screen.queryByText('Drawn')).not.toBeInTheDocument();
    rerender(<ErrorBoundary resetKeys={['paths', 2]}><Part broken={false} /></ErrorBoundary>);
    expect(screen.getByText('Drawn')).toBeInTheDocument();
    expect(screen.queryByText('Unknown node type: widget')).not.toBeInTheDocument();
  });
});
