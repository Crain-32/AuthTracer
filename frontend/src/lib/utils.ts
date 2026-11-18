// @supports UI
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

/** Tailwind classes, later ones winning over earlier conflicting ones. */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}

/** The common leading path segments of routes: /owners for /owners and /owners/{id}. */
export function commonPrefix(routes: string[]): string {
  const segments = routes.map(route => route.split('/').filter(Boolean));
  if (!segments.length) {
    return '';
  }
  const common = segments.reduce((prefix, route) => {
    let length = 0;
    while (length < prefix.length && prefix[length] === route[length]) {
      length++;
    }
    return prefix.slice(0, length);
  });
  return common.length ? '/' + common.join('/') : '';
}

/** Items by key, each list in the items' order. */
export function groupBy<T>(items: Iterable<T>, key: (item: T) => string): Map<string, T[]> {
  const groups = new Map<string, T[]>();
  for (const item of items) {
    const name = key(item);
    const group = groups.get(name);
    if (group) {
      group.push(item);
    }
    else {
      groups.set(name, [item]);
    }
  }
  return groups;
}

/**
 * Consecutive items with the same key, as runs. An item whose key is null stands alone. The views use it to fold
 * endpoints that read the same into one line.
 */
export function runsBy<T>(items: T[], key: (item: T) => string | null): T[][] {
  const runs: T[][] = [];
  let lastKey: string | null = null;
  for (const item of items) {
    const itemKey = key(item);
    const last = runs.at(-1);
    if (last && itemKey !== null && itemKey === lastKey) {
      last.push(item);
    }
    else {
      runs.push([item]);
    }
    lastKey = itemKey;
  }
  return runs;
}

/** A route's first path segment: /actuator for /actuator/health, so a framework's endpoints stay apart. */
export function firstSegment(route: string): string {
  return route.split('/')[1] ?? '';
}
