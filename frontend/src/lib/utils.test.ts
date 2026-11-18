import { describe, expect, it } from 'vitest';

import { cn, commonPrefix, firstSegment, runsBy } from './utils';

describe('cn', () => {
  it('lets a later Tailwind class win over an earlier one it conflicts with, and drops falsy ones', () => {
    expect(cn('px-2 text-sm', false, undefined, 'px-4')).toBe('text-sm px-4');
  });
});

describe('commonPrefix', () => {
  it('is empty for no routes, and for routes that share no segment', () => {
    expect(commonPrefix([])).toBe('');
    expect(commonPrefix(['/owners', '/vets'])).toBe('');
    expect(commonPrefix(['/actuator/health', '/actuator/info', '/actuator/health/db'])).toBe('/actuator');
  });
});

describe('runsBy', () => {
  it('runs consecutive items with the same key; an item with no key stands alone', () => {
    const items = ['a1', 'a2', 'x', 'x', 'b1', 'a3'];
    expect(runsBy(items, item => (item === 'x' ? null : item[0]))).toEqual([['a1', 'a2'], ['x'], ['x'], ['b1'], ['a3']]);
    expect(runsBy([], item => item)).toEqual([]);
  });
});

describe('firstSegment', () => {
  it('is a route\'s first path segment, or empty', () => {
    expect(firstSegment('/actuator/health')).toBe('actuator');
    expect(firstSegment('/')).toBe('');
    expect(firstSegment('')).toBe('');
  });
});
