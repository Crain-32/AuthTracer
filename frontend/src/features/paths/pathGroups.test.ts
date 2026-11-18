import { describe, expect, it } from 'vitest';

import { app, check, egress, endpoint, ingress, link, model } from '@/test/graphs';

import { isBare, matches, mergePaths, runs, servicesOf } from './pathGroups';
import { drawOrder, layout } from './pathLayout';

describe('mergePaths', () => {
  it('puts endpoints that end the same way in one card, sharing the steps after they meet', () => {
    const graph = app('a', [ingress('/one'), ingress('/two'), ingress('/three'), check('location:shared'),
      check('location:other', ['ROLE_USER'])], {
      'ingress:GET /one': ['location:shared'],
      'ingress:GET /two': ['location:shared'],
      'ingress:GET /three': ['location:other'],
    });
    const m = model([graph]);
    const groups = mergePaths(m, m.ingresses('a'), true);
    expect(groups).toHaveLength(2);
    const shared = groups.find(group => group.roots.length === 2)!;
    expect(shared.roots.map(root => root.ingress)).toEqual(['a/ingress:GET /one', 'a/ingress:GET /two']);
    // The shared check is one node: two ingresses and one check.
    expect(shared.nodes.size).toBe(3);
  });

  it('keeps steps apart when what follows them differs, so every drawn path is real', () => {
    const graph = app('a', [ingress('/one'), ingress('/two'), check('location:first'), check('location:x'),
      check('location:y')], {
      'ingress:GET /one': ['location:first', 'location:x'],
      'ingress:GET /two': ['location:first', 'location:y'],
    });
    const m = model([graph]);
    const groups = mergePaths(m, m.ingresses('a'), true);
    expect(groups).toHaveLength(2);
  });

  it('lists endpoints with no steps in one card per service', () => {
    const graph = app('a', [ingress('/one'), ingress('/two'), ingress('/three')]);
    const m = model([graph]);
    const groups = mergePaths(m, m.ingresses('a'), true);
    expect(groups).toHaveLength(1);
    expect(isBare(groups[0])).toBe(true);
    expect(groups[0].roots).toHaveLength(3);
  });

  it('draws the same path in several services once, naming the twins', () => {
    const health = (service: string) => app(service, [ingress('/actuator/health'), check('location:health', [])],
      { 'ingress:GET /actuator/health': ['location:health'] });
    const m = model([health('a'), health('b')]);
    const groups = mergePaths(m, [...m.ingresses('a'), ...m.ingresses('b')], true);
    expect(groups).toHaveLength(1);
    expect(groups[0].twins.map(twin => twin.roots[0].node.service)).toEqual(['b']);
  });

  it('follows a call into the service it reaches when following links', () => {
    const caller = app('a', [ingress('/profiles'), egress('egress:call', '/employees')],
      { 'ingress:GET /profiles': ['egress:call'] });
    const callee = app('b', [ingress('/employees'), check('location:b')], { 'ingress:GET /employees': ['location:b'] });
    const link = { from: 'a/egress:call', to: 'b/ingress:GET /employees', kind: 'NETWORK_INFERRED' as const, order: 0,
      via: [], bidirectional: true };
    const m = model([caller, callee], [link]);
    const followed = mergePaths(m, m.ingresses('a'), true);
    expect(followed[0].roots[0].checks).toBe(1);
    expect(mergePaths(m, m.ingresses('a'), false)[0].roots[0].checks).toBe(0);
    // The callee's lane comes below its caller's.
    expect(layout(followed[0]).lanes.map(lane => lane.service)).toEqual(['a', 'b']);
  });
});

describe('layout', () => {
  it('places each step after the one before it, and joins shared steps', () => {
    const graph = app('a', [ingress('/one'), ingress('/two'), check('location:shared')], {
      'ingress:GET /one': ['location:shared'],
      'ingress:GET /two': ['location:shared'],
    });
    const m = model([graph]);
    const [group] = mergePaths(m, m.ingresses('a'), true);
    const plan = layout(group);
    const [one, two] = group.roots;
    const shared = one.node.next!;
    expect(plan.at.get(shared)!.x).toBeGreaterThan(plan.at.get(one.node)!.x);
    expect(plan.at.get(one.node)!.y).not.toBe(plan.at.get(two.node)!.y);
    expect(drawOrder(group, plan).map(root => root.ingress)).toEqual([one.ingress, two.ingress]);
  });
});

describe('runs', () => {
  it('sums up consecutive endpoints that read the same', () => {
    const graph = app('a', ['/x/1', '/x/2', '/x/3', '/y'].map(route => ingress(route)));
    const m = model([graph]);
    const [group] = mergePaths(m, m.ingresses('a'), true);
    expect(runs(m, group.roots).map(run => run.length)).toEqual([3, 1]);
  });

  it('keeps endpoints apart that need something else or have other callers', () => {
    const graph = app('a', ['/x/1', '/x/2', '/x/3', '/x/4'].map(route => ingress(route)));
    const m = model([graph, app('b', [egress('egress:call', '/x/4')])], [link('b/egress:call', 'a/ingress:GET /x/4')],
      [endpoint('a', '/x/1', 'none'), endpoint('a', '/x/2', 'none'), endpoint('a', '/x/3', 'ROLE_A'),
        endpoint('a', '/x/4', 'ROLE_A')]);
    const [group] = mergePaths(m, m.ingresses('a'), true);
    expect(runs(m, group.roots).map(run => run.map(root => root.ingress.slice(-3)))).toEqual([['x/1', 'x/2'], ['x/3'],
      ['x/4']]);
  });
});

describe('merging', () => {
  it('joins two cards when an endpoint reaches the steps of both', () => {
    const a = app('a', [ingress('/one'), ingress('/three'), check('location:x'), egress('egress:call', '/b')], {
      'ingress:GET /one': ['location:x'],
      'ingress:GET /three': ['egress:call', 'location:x'],
    });
    const b = app('b', [ingress('/b'), ingress('/two'), check('location:y')], {
      'ingress:GET /b': ['location:y'],
      'ingress:GET /two': ['location:y'],
    });
    const m = model([a, b], [link('a/egress:call', 'b/ingress:GET /b')]);
    const groups = mergePaths(m, ['a/ingress:GET /one', 'b/ingress:GET /two', 'a/ingress:GET /three'], true);
    expect(groups).toHaveLength(1);
    expect(groups[0].roots.map(root => root.ingress)).toEqual(['a/ingress:GET /one', 'b/ingress:GET /two',
      'a/ingress:GET /three']);
    // Three ingresses, both checks once, the egress and the ingress it calls.
    expect(groups[0].nodes.size).toBe(7);
    expect(groups[0].roots.map(root => root.checks)).toEqual([1, 1, 2]);
  });

  it('keeps a step apart whose next step runs on some branches only, so its arrow stays dashed', () => {
    const graph = app('a', [ingress('/one'), ingress('/two'), check('location:first'), check('location:then')], {
      'ingress:GET /one': ['location:first', 'location:then'],
      'ingress:GET /two': ['location:first', 'location:then'],
    });
    graph.edges[1].conditional = true;
    const m = model([graph]);
    const [group] = mergePaths(m, m.ingresses('a'), true);
    const [one, two] = group.roots;
    expect(one.node.next).not.toBe(two.node.next);
    expect(one.node.next!.nextEdge?.conditional).toBe(true);
    expect(two.node.next!.nextEdge?.conditional).toBeUndefined();
    // The step both reach after it is still one.
    expect(one.node.next!.next).toBe(two.node.next!.next);
  });

  it('names the services a card stands for: its own, then its twins\'', () => {
    const health = (service: string) => app(service, [ingress('/actuator/health'), check('location:health', [])],
      { 'ingress:GET /actuator/health': ['location:health'] });
    const m = model(['a', 'b', 'c'].map(health));
    const [group] = mergePaths(m, m.services.flatMap(service => m.ingresses(service)), true);
    expect(servicesOf(group)).toEqual(['a', 'b', 'c']);
    expect(group.key).toBe('a/ingress:GET /actuator/health b/ingress:GET /actuator/health c/ingress:GET /actuator/health');
  });

  it('draws twins apart when their endpoints need something else', () => {
    const health = (service: string) => app(service, [ingress('/actuator/health'), check('location:health', [])],
      { 'ingress:GET /actuator/health': ['location:health'] });
    const m = model([health('a'), health('b')], [],
      [endpoint('a', '/actuator/health', 'none'), endpoint('b', '/actuator/health', 'ROLE_ACTUATOR')]);
    expect(mergePaths(m, [...m.ingresses('a'), ...m.ingresses('b')], true)).toHaveLength(2);
  });
});

describe('matches', () => {
  it('needs every word in the endpoints, services or requirements of a card or its twins', () => {
    const health = (service: string) => app(service, [ingress('/actuator/health'), check('location:health', [])],
      { 'ingress:GET /actuator/health': ['location:health'] });
    const m = model([health('profile-service'), health('employee-service')], [],
      [endpoint('profile-service', '/actuator/health', 'permitAll'), endpoint('employee-service', '/actuator/health', 'permitAll')]);
    const [group] = mergePaths(m, [...m.ingresses('profile-service'), ...m.ingresses('employee-service')], true);
    expect(matches(m, group, [])).toBe(true);
    expect(matches(m, group, ['get', '/actuator/health'])).toBe(true);
    expect(matches(m, group, ['employee-service', 'permitall'])).toBe(true);
    expect(matches(m, group, ['identity-service'])).toBe(false);
    expect(matches(m, group, ['health', 'post'])).toBe(false);
  });

  it('matches an endpoint the server worked out no exposure for by its route and service', () => {
    const m = model([app('a', [ingress('/owners')])]);
    const [group] = mergePaths(m, m.ingresses('a'), true);
    expect(matches(m, group, ['a', 'get', 'owners'])).toBe(true);
    expect(matches(m, group, ['none'])).toBe(false);
  });
});
