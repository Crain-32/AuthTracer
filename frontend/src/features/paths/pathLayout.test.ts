import { describe, expect, it } from 'vitest';

import { app, check, egress, ingress, link, model } from '@/test/graphs';

import { mergePaths, type PathNode } from './pathGroups';
import { drawOrder, layout, STEP_H, STEP_W, stepPosition } from './pathLayout';

/** The merged step of one qualified node id. */
const step = (nodes: Set<PathNode>, qid: string) => [...nodes].find(node => node.qid === qid)!;

describe('layout', () => {
  it('puts the caller\'s next step after everything the service it calls does', () => {
    const caller = app('a', [ingress('/profiles'), egress('egress:call', '/employees'), check('location:after')],
      { 'ingress:GET /profiles': ['egress:call', 'location:after'] });
    const callee = app('b', [ingress('/employees'), check('location:b1'), check('location:b2')],
      { 'ingress:GET /employees': ['location:b1', 'location:b2'] });
    const m = model([caller, callee], [link('a/egress:call', 'b/ingress:GET /employees')]);
    const [group] = mergePaths(m, m.ingresses('a'), true);
    const plan = layout(group);
    const x = (qid: string) => plan.at.get(step(group.nodes, qid))!.x;
    expect(x('b/ingress:GET /employees')).toBeGreaterThan(x('a/egress:call'));
    expect(x('a/location:after')).toBeGreaterThan(x('b/location:b2'));
    // Six columns, one row in each of two lanes.
    expect(plan.width).toBeGreaterThan(5 * STEP_W);
    expect(plan.lanes.map(lane => lane.service)).toEqual(['a', 'b']);
    expect(plan.lanes[1].top).toBeGreaterThan(plan.lanes[0].top + STEP_H);
  });

  it('draws an endpoint two calls reach once, on one row, both callers going on after it', () => {
    const caller = app('a', [ingress('/one'), ingress('/two'), egress('egress:1', '/x'), egress('egress:2', '/x'),
      check('location:1'), check('location:2')],
    { 'ingress:GET /one': ['egress:1', 'location:1'], 'ingress:GET /two': ['egress:2', 'location:2'] });
    const callee = app('b', [ingress('/x'), check('location:x')], { 'ingress:GET /x': ['location:x'] });
    const m = model([caller, callee], [link('a/egress:1', 'b/ingress:GET /x'), link('a/egress:2', 'b/ingress:GET /x')]);
    const [group] = mergePaths(m, m.ingresses('a'), true);
    const plan = layout(group);
    const [callerLane, calleeLane] = plan.lanes;
    expect(calleeLane.service).toBe('b');
    // The caller's lane has two rows, the callee's one.
    expect(callerLane.height - calleeLane.height).toBe(STEP_H + 18);
    const at = (qid: string) => plan.at.get(step(group.nodes, qid))!;
    expect(at('b/location:x').y).toBe(at('b/ingress:GET /x').y);
    expect(at('a/location:1').x).toBe(at('a/location:2').x);
    expect(at('a/location:1').x).toBeGreaterThan(at('b/location:x').x);
  });

  it('waits for the calls a called service makes before the caller goes on', () => {
    const a = app('a', [ingress('/p'), egress('egress:a', '/q'), check('location:after')],
      { 'ingress:GET /p': ['egress:a', 'location:after'] });
    const b = app('b', [ingress('/q'), egress('egress:b', '/r')], { 'ingress:GET /q': ['egress:b'] });
    const c = app('c', [ingress('/r'), check('location:c')], { 'ingress:GET /r': ['location:c'] });
    const m = model([a, b, c], [link('a/egress:a', 'b/ingress:GET /q'), link('b/egress:b', 'c/ingress:GET /r')]);
    const [group] = mergePaths(m, ['a/ingress:GET /p'], true);
    const plan = layout(group);
    expect(plan.lanes.map(lane => lane.service)).toEqual(['a', 'b', 'c']);
    const x = (qid: string) => plan.at.get(step(group.nodes, qid))!.x;
    expect(x('a/location:after')).toBeGreaterThan(x('c/location:c'));
  });

  it('keeps a service that calls itself in its own lane, the call\'s steps after it on the same row', () => {
    const graph = app('a', [ingress('/p'), ingress('/internal'), egress('egress:self', '/internal'), check('location:x')],
      { 'ingress:GET /p': ['egress:self'], 'ingress:GET /internal': ['location:x'] });
    const m = model([graph], [link('a/egress:self', 'a/ingress:GET /internal')]);
    const [group] = mergePaths(m, ['a/ingress:GET /p'], true);
    const plan = layout(group);
    expect(plan.lanes.map(lane => lane.service)).toEqual(['a']);
    const at = (qid: string) => plan.at.get(step(group.nodes, qid))!;
    expect(at('a/location:x').y).toBe(at('a/ingress:GET /p').y);
    expect(at('a/location:x').x).toBeGreaterThan(at('a/egress:self').x);
  });

  it('keeps a row free up to the step its arrow joins, so no other step stands on the way', () => {
    // /employees is reached by a call, two columns in; /other joins its check from the first column.
    const caller = app('a', [ingress('/profiles'), egress('egress:call', '/employees')],
      { 'ingress:GET /profiles': ['egress:call'] });
    const callee = app('b', [ingress('/employees'), ingress('/other'), check('location:y')],
      { 'ingress:GET /employees': ['location:y'], 'ingress:GET /other': ['location:y'] });
    const m = model([caller, callee], [link('a/egress:call', 'b/ingress:GET /employees')]);
    const [group] = mergePaths(m, ['a/ingress:GET /profiles', 'b/ingress:GET /other'], true);
    const plan = layout(group);
    const at = (qid: string) => plan.at.get(step(group.nodes, qid))!;
    expect(at('b/ingress:GET /other').x).toBeLessThan(at('b/ingress:GET /employees').x);
    expect(at('b/ingress:GET /other').y).toBeGreaterThan(at('b/ingress:GET /employees').y);
    // The arrow turns in the gap before the check, halfway when the steps are next to each other.
    const bend = stepPosition(at('b/ingress:GET /other'), at('b/location:y'));
    const start = at('b/ingress:GET /other').x + STEP_W + 20;
    expect(start + bend * (at('b/location:y').x - 20 - start)).toBe(at('b/location:y').x - 26);
    expect(stepPosition(at('b/ingress:GET /employees'), at('b/location:y'))).toBe(0.5);
  });

  it('draws called endpoints in their callers\' order, so the arrows between lanes don\'t cross', () => {
    const caller = app('a', [ingress('/profiles'), ingress('/profiles/{id}'), egress('egress:all', '/employees'),
      egress('egress:one', '/employee')],
    { 'ingress:GET /profiles': ['egress:all'], 'ingress:GET /profiles/{id}': ['egress:one'] });
    // Both end with the same field check, so the four endpoints share one card.
    const callee = app('b', [ingress('/employee'), ingress('/employees'), check('location:one'), check('location:all'),
      check('location:salary')], { 'ingress:GET /employee': ['location:one', 'location:salary'],
      'ingress:GET /employees': ['location:all', 'location:salary'] });
    const m = model([caller, callee], [link('a/egress:all', 'b/ingress:GET /employees'),
      link('a/egress:one', 'b/ingress:GET /employee')]);
    // The called endpoints come first, as their own service lists them.
    const [group] = mergePaths(m, ['b/ingress:GET /employee', 'b/ingress:GET /employees', 'a/ingress:GET /profiles',
      'a/ingress:GET /profiles/{id}'], true);
    const plan = layout(group);
    const y = (qid: string) => plan.at.get(step(group.nodes, qid))!.y;
    expect(y('a/egress:all')).toBeLessThan(y('a/egress:one'));
    // Crossing arrows of the same length would put their "N calls" labels on top of each other.
    expect(y('b/ingress:GET /employees')).toBeLessThan(y('b/ingress:GET /employee'));
  });

  it('puts lanes in the order they appear when services call each other', () => {
    const a = app('a', [ingress('/p'), ingress('/r'), egress('egress:a', '/q'), check('location:r')],
      { 'ingress:GET /p': ['egress:a'], 'ingress:GET /r': ['location:r'] });
    const b = app('b', [ingress('/q'), egress('egress:b', '/r')], { 'ingress:GET /q': ['egress:b'] });
    const m = model([a, b], [link('a/egress:a', 'b/ingress:GET /q'), link('b/egress:b', 'a/ingress:GET /r')]);
    const [group] = mergePaths(m, ['a/ingress:GET /p'], true);
    expect(group.roots[0].checks).toBe(1);
    expect(layout(group).lanes.map(lane => lane.service)).toEqual(['a', 'b']);
  });
});

describe('drawOrder', () => {
  it('lists endpoints by lane, then row, then column', () => {
    const caller = app('a', [ingress('/profiles'), egress('egress:call', '/employees')],
      { 'ingress:GET /profiles': ['egress:call'] });
    const callee = app('b', [ingress('/employees'), ingress('/other'), check('location:y')],
      { 'ingress:GET /employees': ['location:y'], 'ingress:GET /other': ['location:y'] });
    const m = model([caller, callee], [link('a/egress:call', 'b/ingress:GET /employees')]);
    const [group] = mergePaths(m, ['a/ingress:GET /profiles', 'b/ingress:GET /other', 'b/ingress:GET /employees'], true);
    const plan = layout(group);
    // /other starts left of /employees, but its arrow to the check they share needs a row of its own, below.
    expect(drawOrder(group, plan).map(root => root.ingress)).toEqual(['a/ingress:GET /profiles',
      'b/ingress:GET /employees', 'b/ingress:GET /other']);
    // On one row, the one further left comes first.
    const [, other, employees] = group.roots;
    const row = plan.at.get(employees.node)!.y;
    const at = new Map(plan.at).set(other.node, { x: 0, y: row });
    expect(drawOrder(group, { ...plan, at }).map(root => root.ingress)).toEqual(['a/ingress:GET /profiles',
      'b/ingress:GET /other', 'b/ingress:GET /employees']);
  });
});
