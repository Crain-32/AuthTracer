import { act, renderHook, screen } from '@testing-library/react';
import { useRef } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { useElementWidth } from '@/hooks/useElementWidth';
import { useInView } from '@/hooks/useInView';
import { layout, viewport } from '@/test/dom';
import { renderUi } from '@/test/render';

import { ScaledFlow } from './ScaledFlow';

const nodes = [{ id: 'a', position: { x: 0, y: 0 }, data: { label: 'A step' } }];

/** A diagram this wide and high, in the page's scrolling area as the views put it. */
function renderFlow(width: number, height = 100) {
  return renderUi(<main><ScaledFlow width={width} height={height} minHeight={120} nodes={nodes} edges={[]} /></main>);
}

const sized = () => screen.getByTestId('rf__wrapper').parentElement!;

afterEach(() => vi.unstubAllGlobals());

describe('ScaledFlow', () => {
  it('shrinks a wide diagram to fit, down to four fifths, and keeps its height at least the minimum', async () => {
    layout.width = 900;
    renderFlow(1000, 400);
    expect(await screen.findByText('A step')).toBeInTheDocument();
    expect(sized()).toHaveStyle({ width: '900px', height: '360px' });
  });

  it('scrolls a diagram sideways past four fifths, and never enlarges a narrow one', async () => {
    layout.width = 1000;
    const { unmount } = renderFlow(2000);
    await screen.findByText('A step');
    expect(sized()).toHaveStyle({ width: '1600px', height: '120px' });
    unmount();
    renderFlow(500);
    await screen.findByText('A step');
    expect(sized()).toHaveStyle({ width: '500px' });
  });

  it('draws only once the diagram comes near the page\'s visible part, measured from the scrolling area', async () => {
    viewport.held = true;
    renderFlow(500);
    await act(async () => {});
    expect(screen.queryByTestId('rf__wrapper')).not.toBeInTheDocument();
    expect(viewport.options).toEqual([{ root: screen.getByRole('main'), rootMargin: '400px' }]);
    act(() => viewport.release());
    expect(await screen.findByText('A step')).toBeInTheDocument();
  });

  it('draws at once where the browser can\'t tell what is in view', async () => {
    vi.stubGlobal('IntersectionObserver', undefined);
    renderFlow(500);
    expect(await screen.findByText('A step')).toBeInTheDocument();
  });
});

describe('the hooks, with no element attached', () => {
  it('measure nothing and never report it in view', () => {
    const width = renderHook(() => useElementWidth<HTMLDivElement>());
    expect(width.result.current[1]).toBe(0);
    const near = renderHook(() => useInView(useRef<Element>(null)));
    expect(near.result.current).toBe(false);
    expect(viewport.options).toEqual([]);
  });
});
