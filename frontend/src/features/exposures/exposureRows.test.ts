import { describe, expect, it } from 'vitest';

import { endpoint } from '@/test/graphs';

import { alikeRuns, beyond, endpointGroups, matchesFilter, runPrefix, sharedAddition } from './exposureRows';

describe('endpointGroups', () => {
  it('names every service in one row when the same endpoint needs the same in each', () => {
    const groups = endpointGroups(['a', 'b'].map(service => endpoint(service, '/actuator/health', 'none')));
    expect(groups).toHaveLength(1);
    expect(groups[0][0].service).toBe('a, b');
    expect(groups[0][0].services).toEqual(['a', 'b']);
  });

  it('keeps an endpoint with fields apart', () => {
    const groups = endpointGroups([endpoint('a', '/p', 'ROLE_A'), endpoint('a', '/p', 'ROLE_A', 'name'),
      endpoint('b', '/p', 'ROLE_A')]);
    expect(groups.map(group => group.length)).toEqual([2, 1]);
  });
});

describe('endpointGroups of many services', () => {
  it('counts the services past three, and keeps an endpoint that breaks a policy apart', () => {
    const groups = endpointGroups(['a', 'b', 'c', 'd'].map(service => endpoint(service, '/actuator/health', 'none')));
    expect(groups).toHaveLength(1);
    expect(groups[0][0]).toMatchObject({ service: '4 services', services: ['a', 'b', 'c', 'd'] });
    const violating = { ...endpoint('b', '/actuator/health', 'none'), violations: [{ label: 'OPS', requires: 'ROLE_OPS' }] };
    expect(endpointGroups([endpoint('a', '/actuator/health', 'none'), violating])).toHaveLength(2);
  });

  it('keeps endpoints that need something else apart', () => {
    const groups = endpointGroups([endpoint('a', '/actuator/health', 'none'), endpoint('b', '/actuator/health', 'ROLE_A')]);
    expect(groups.map(group => group[0].service)).toEqual(['a', 'b']);
  });
});

describe('alikeRuns', () => {
  it('runs endpoints of one service, requirement and first segment together', () => {
    const groups = endpointGroups(['/actuator/a', '/actuator/b', '/api/c'].map(route => endpoint('a', route, 'none')));
    const runs = alikeRuns(groups);
    expect(runs.map(run => run.length)).toEqual([2, 1]);
    expect(runPrefix(runs[0])).toBe('/actuator');
  });

  it('leaves an endpoint with fields, or one that breaks a policy, out of every run', () => {
    const violating = { ...endpoint('a', '/api/c', 'none'), violations: [{ label: 'PII', requires: 'ROLE_HR' }] };
    const groups = endpointGroups([endpoint('a', '/api/a', 'none'), endpoint('a', '/api/b', 'none'),
      endpoint('a', '/api/b', 'none', 'name'), violating, endpoint('a', '/api/d', 'none')]);
    expect(alikeRuns(groups).map(run => run.map(group => group[0].endpoint))).toEqual([['GET /api/a'], ['GET /api/b'],
      ['GET /api/c'], ['GET /api/d']]);
  });
});

describe('sharedAddition', () => {
  it('finds what every field adds first', () => {
    const fields = ['x', 'y'].map(field => ({ ...endpoint('a', '/p', 'R', field), adds: 'F and ROLE_ADMIN' }));
    fields[1].adds = 'F';
    expect(sharedAddition(fields)).toBe('F');
    expect(beyond('F and ROLE_ADMIN', 'F')).toBe('ROLE_ADMIN');
    expect(beyond('F', 'F')).toBe('');
  });

  it('is nothing for a single field, or when a field adds nothing the server could tell', () => {
    const field = (name: string, adds: string | null) => ({ ...endpoint('a', '/p', 'R', name), adds });
    expect(sharedAddition([field('x', 'F')])).toBe('');
    expect(sharedAddition([field('x', 'F'), field('y', null)])).toBe('');
    expect(sharedAddition([field('x', 'F'), field('y', '')])).toBe('');
    expect(sharedAddition([field('x', 'F and A'), field('y', 'G and A')])).toBe('');
    expect(beyond('ROLE_ADMIN', '')).toBe('ROLE_ADMIN');
  });
});

describe('matchesFilter', () => {
  it('needs every word somewhere in the row', () => {
    const exposure = { ...endpoint('profile-service', '/profiles', 'SCOPE_x'), labels: ['PII'] };
    expect(matchesFilter(exposure, ['profile-service', 'pii'])).toBe(true);
    expect(matchesFilter(exposure, ['employee-service'])).toBe(false);
  });

  it('finds the policies a row breaks and the checks on its way', () => {
    const exposure = { ...endpoint('profile-service', '/profiles', 'SCOPE_x', 'ssn'),
      violations: [{ label: 'PII', requires: 'ROLE_HR' }],
      steps: [{ location: 'employee-service/location:ssn', mechanism: '@PreAuthorize', requirement: 'ROLE_ADMIN' }] };
    expect(matchesFilter(exposure, ['policy', 'violation', 'pii'])).toBe(true);
    expect(matchesFilter(exposure, ['@preauthorize', 'role_admin'])).toBe(true);
    expect(matchesFilter(exposure, ['employee-service/location:ssn'])).toBe(true);
    expect(matchesFilter(exposure, ['ssn', 'postfilter'])).toBe(false);
  });
});
