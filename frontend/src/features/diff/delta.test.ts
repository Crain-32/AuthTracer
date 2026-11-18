import { describe, expect, it } from 'vitest';

import { changeGroups, deltaOf, terms } from './delta';

describe('terms', () => {
  it('splits on top-level "and" only', () => {
    expect(terms('A and (B and C) and D')).toEqual(['A', '(B and C)', 'D']);
  });
});

describe('deltaOf', () => {
  it('shows removed and added terms', () => {
    expect(deltaOf({ before: 'A and B', after: 'A and C' })).toMatchObject({ removed: ['B'], added: ['C'] });
  });

  it('falls back to before → after, or new / was', () => {
    expect(deltaOf({ before: 'A', after: 'A' }).plain).toBe('A → A');
    expect(deltaOf({ before: null, after: 'A' }).plain).toBe('new: A');
    expect(deltaOf({ before: 'A', after: null }).plain).toBe('was: A');
  });
});

describe('changeGroups', () => {
  it('lists the places of one change on one row', () => {
    const change = (endpoint: string) => ({ kind: 'WEAKENED', severity: 'FAIL' as const, service: 's', endpoint,
      before: 'A and B', after: 'A' });
    expect(changeGroups([change('GET /x'), change('GET /y')])).toHaveLength(1);
  });

  it('keeps each new finding on its own row, and the report\'s order', () => {
    const finding = (message: string) => ({ kind: 'NEW_FINDING', severity: 'REVIEW' as const, service: 's',
      endpoint: 'x.Foo#bar()', after: 'BYPASSED', message });
    const weakened = { kind: 'WEAKENED', severity: 'FAIL' as const, service: 's', endpoint: 'GET /x', before: 'A',
      after: 'none' };
    const groups = changeGroups([weakened, finding('one'), finding('two'), finding('one')]);
    expect(groups.map(group => [group.change.kind, group.places.length, group.delta.text])).toEqual([
      ['WEAKENED', 1, '− A + none'], ['NEW_FINDING', 2, 'new: BYPASSED'], ['NEW_FINDING', 1, 'new: BYPASSED']]);
    expect(groups[1].places.map(place => place.message)).toEqual(['one', 'one']);
  });
});
