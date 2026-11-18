import { describe, expect, it } from 'vitest';

import type { ServiceFinding } from '@/lib/model';

import { findingGroups } from './findingGroups';

const finding = (message: string, service = 'a', kind = 'BYPASSED'): ServiceFinding => ({ service, kind, message });

describe('findingGroups', () => {
  it('merges messages that differ in one word, keeping what fills the blank per finding', () => {
    const groups = findingGroups(['audit', 'orders.list', 'profile.{name}'].map(route =>
      finding(`client calls server RSOCKET ${route} with fixed credentials`)));
    expect(groups).toHaveLength(1);
    expect(groups[0].template).toEqual(['client', 'calls', 'server', 'RSOCKET', null, 'with', 'fixed', 'credentials']);
    expect(groups[0].values).toEqual([['audit'], ['orders.list'], ['profile.{name}']]);
  });

  it('keeps the values of two blanks together per finding', () => {
    const groups = findingGroups([
      finding('Actuator shutdown (POST /actuator/shutdown) answers anyone: it stops the application'),
      finding('Actuator loggers (POST /actuator/loggers) answers anyone: it stops the application'),
    ]);
    expect(groups).toHaveLength(1);
    expect(groups[0].values).toEqual([['shutdown', '/actuator/shutdown)'], ['loggers', '/actuator/loggers)']]);
  });

  it('keeps apart other services, other kinds and messages that share too little', () => {
    const message = 'one two three four five six seven eight';
    expect(findingGroups([finding(message), finding(message, 'b')])).toHaveLength(2);
    expect(findingGroups([finding(message), finding(message, 'a', 'NOT_ENFORCED')])).toHaveLength(2);
    expect(findingGroups([finding('a b c d'), finding('a x y d')])).toHaveLength(2);
    expect(findingGroups([finding(message), finding('one 2 3 4 five six seven eight')])).toHaveLength(2);
  });

  it('merges identical messages from different places', () => {
    const groups = findingGroups([finding('the same words every time'), finding('the same words every time')]);
    expect(groups).toHaveLength(1);
    expect(groups[0].template.every(word => word !== null)).toBe(true);
  });
});
