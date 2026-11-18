/**
 * What a browser has and jsdom lacks, for the component tests: the observers the diagrams wait for, and what React
 * Flow and Radix measure with. Tests change the reported width, or hold intersections back, through these.
 */

/** The width every observed element reports: the diagrams draw only once their container has one. */
export const layout = { width: 1200 };

/** Reports each observed element's size once, after the effects that observed it, as a browser does after layout. */
class ResizeObserverStub implements ResizeObserver {
  private disconnected = false;

  constructor(private readonly callback: ResizeObserverCallback) {}

  observe(target: Element) {
    const rect = { x: 0, y: 0, top: 0, left: 0, width: layout.width, height: 800, right: layout.width, bottom: 800 };
    queueMicrotask(() => {
      if (!this.disconnected) {
        this.callback([{ target, contentRect: rect } as unknown as ResizeObserverEntry], this);
      }
    });
  }

  unobserve() {}

  disconnect() {
    this.disconnected = true;
  }
}

/** Every element is in view as soon as it is observed, unless a test sets `held` and calls `release()`. */
export const viewport = {
  held: false,
  options: [] as (IntersectionObserverInit | undefined)[],
  waiting: [] as (() => void)[],
  release() {
    this.waiting.splice(0).forEach(enter => enter());
  },
};

class IntersectionObserverStub implements IntersectionObserver {
  readonly root = null;
  readonly rootMargin = '';
  readonly scrollMargin = '';
  readonly thresholds = [];
  private disconnected = false;

  constructor(private readonly callback: IntersectionObserverCallback, options?: IntersectionObserverInit) {
    viewport.options.push(options);
  }

  /** Reports the element far from view first, as a browser does for a diagram below the fold, then near it. */
  observe(target: Element) {
    const report = (isIntersecting: boolean) => {
      if (!this.disconnected) {
        this.callback([{ target, isIntersecting } as unknown as IntersectionObserverEntry], this);
      }
    };
    report(false);
    if (viewport.held) {
      viewport.waiting.push(() => report(true));
    }
    else {
      report(true);
    }
  }

  unobserve() {}

  disconnect() {
    this.disconnected = true;
  }

  takeRecords(): IntersectionObserverEntry[] {
    return [];
  }
}

/** React Flow reads the viewport's zoom from its transform. */
class DOMMatrixReadOnlyStub {
  readonly m22: number;

  constructor(transform?: string) {
    const scale = transform?.match(/scale\(([\d.]+)\)/)?.[1];
    this.m22 = scale === undefined ? 1 : Number(scale);
  }
}

export function installBrowserStubs() {
  globalThis.ResizeObserver = ResizeObserverStub;
  globalThis.IntersectionObserver = IntersectionObserverStub;
  globalThis.DOMMatrixReadOnly = DOMMatrixReadOnlyStub as unknown as typeof DOMMatrixReadOnly;
  // React Flow measures nodes by their offset size, and hides those that have none.
  Object.defineProperties(HTMLElement.prototype, {
    offsetWidth: { configurable: true, get() { return parseFloat(this.style.width) || 1; } },
    offsetHeight: { configurable: true, get() { return parseFloat(this.style.height) || 1; } },
  });
  // Edge labels measure their text; jsdom gives an SVG <text> no interface of its own to hang it on.
  (SVGElement.prototype as SVGGraphicsElement).getBBox = () => ({ x: 0, y: 0, width: 0, height: 0 }) as DOMRect;
  // Radix's select captures the pointer and scrolls its options into view.
  Element.prototype.hasPointerCapture = () => false;
  Element.prototype.setPointerCapture = () => {};
  Element.prototype.releasePointerCapture = () => {};
  Element.prototype.scrollIntoView = () => {};
}
