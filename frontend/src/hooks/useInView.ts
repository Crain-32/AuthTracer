// @supports PATHS_VIEW, LINEAGE_VIEW
import { useEffect, useState, type RefObject } from 'react';

/** Whether an element has come near the visible part of the page yet; once it has, it stays true. */
export function useInView(ref: RefObject<Element | null>, margin = '400px'): boolean {
  const [seen, setSeen] = useState(typeof IntersectionObserver === 'undefined');
  useEffect(() => {
    const element = ref.current;
    if (seen || !element) {
      return;
    }
    const observer = new IntersectionObserver(entries => {
      if (entries.some(entry => entry.isIntersecting)) {
        setSeen(true);
      }
    // Rooted at the page's scrolling area, so the margin reaches past its clipping.
    }, { root: element.closest('main'), rootMargin: margin });
    observer.observe(element);
    return () => observer.disconnect();
  }, [ref, seen, margin]);
  return seen;
}
