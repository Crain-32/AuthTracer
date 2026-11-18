// @supports UI
import { TriangleAlert } from 'lucide-react';
import { Component, type ReactNode } from 'react';

import { EmptyState } from '@/components/common';

interface Props {
  /** When any of these change, the boundary tries its children again. */
  resetKeys: unknown[];
  children: ReactNode;
}

/**
 * A graph this UI doesn't fully understand (a newer backend, a hand-edited file) breaks one view or panel, not the
 * whole page.
 */
export class ErrorBoundary extends Component<Props, { error: Error | null }> {
  state = { error: null as Error | null };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  componentDidUpdate(previous: Props) {
    if (this.state.error && previous.resetKeys.some((key, index) => key !== this.props.resetKeys[index])) {
      this.setState({ error: null });
    }
  }

  render() {
    if (this.state.error) {
      return (
        <EmptyState icon={<TriangleAlert />} title="This part of the graph couldn't be shown">
          {this.state.error.message}
        </EmptyState>
      );
    }
    return this.props.children;
  }
}
