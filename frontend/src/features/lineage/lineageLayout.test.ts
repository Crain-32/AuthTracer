import { describe, expect, it } from 'vitest';

import type { DenialKind, Exposure, ExposureStep, Flow, LocationNode } from '@/lib/types';
import { app, endpoint, field, link, model } from '@/test/graphs';

import {
  anchorOffset, boxTitle, GUARD_H, HEAD_H, lineagePlan, ROW_H, rowHeight, type LineagePlan,
} from './lineageLayout';

const flow = (from: string, to: string, source: Flow['source'] = 'DIRECT'): Flow =>
  ({ path: 'ingress:GET /p', from, to, source, kind: 'LOCAL' });

/** Two fields copied unchanged through a DTO into the response, and one computed from the source. */
function exposures(): Exposure[] {
  const field = (name: string, lineage: Flow[]): Exposure => ({ ...endpoint('a', '/p', 'R', name),
    fieldId: `a/field:x.View.${name}`, lineage });
  return [
    field('id', [flow('a/field:x.Dto.id', 'a/field:x.View.id'), flow('a/field:x.Source.id', 'a/field:x.Dto.id')]),
    field('name', [flow('a/field:x.Dto.name', 'a/field:x.View.name'), flow('a/field:x.Source.name', 'a/field:x.Dto.name')]),
    field('label', [flow('a/field:x.Source.name', 'a/field:x.View.label', 'COMPUTED')]),
  ];
}

describe('lineagePlan', () => {
  it('puts sources left of the response, and copies of several fields share one arrow', () => {
    const plan = lineagePlan(model([app('a', [])]), exposures(), new Set());
    const box = (name: string) => plan.boxes.find(found => found.className.endsWith(name))!;
    expect(box('Source').x).toBeLessThan(box('Dto').x);
    expect(box('Dto').x).toBeLessThan(box('View').x);
    expect(plan.bundles).toHaveLength(2);
    expect(box('View').role).toBe('response');
    expect(box('Source').role).toBe('source');
  });

  it('collapses a class every field passes through unchanged, until it is expanded', () => {
    const m = model([app('a', [])]);
    const collapsed = lineagePlan(m, exposures(), new Set()).boxes.find(found => found.className.endsWith('Dto'))!;
    expect(collapsed.collapsed).toBe(true);
    const expanded = lineagePlan(m, exposures(), new Set([collapsed.key])).boxes
      .find(found => found.className.endsWith('Dto'))!;
    expect(expanded.collapsed).toBe(false);
    expect(expanded.height).toBeGreaterThan(collapsed.height);
  });

  it('attaches arrows to the middle of a field\'s row, the rows one under the other below the class\'s name', () => {
    const plan = lineagePlan(model([app('a', [])]), exposures(), new Set(['a/field:x.Dto']));
    const dto = plan.boxes.find(found => found.className.endsWith('Dto'))!;
    expect(dto.fields.map(anchorOffset)).toEqual([HEAD_H + ROW_H / 2, HEAD_H + ROW_H + ROW_H / 2]);
  });
});

/** A response field of x.View on GET /p, with its lineage and the checks on its way. */
const response = (name: string, lineage: Flow[], more: Partial<Exposure> = {}): Exposure =>
  ({ ...endpoint('a', '/p', 'R', name), fieldId: `a/field:x.View.${name}`, lineage, ...more });

const boxOf = (plan: LineagePlan, className: string) => plan.boxes.find(found => found.className === className)!;
const rowOf = (plan: LineagePlan, qid: string) => plan.boxes.flatMap(found => found.fields).find(row => row.qid === qid)!;

describe('lineage rows', () => {
  it('show the field checks that guard them, each once, with what a denied caller gets', () => {
    const location = (id: string, denial?: DenialKind): LocationNode => ({ type: 'location', id, mechanism: '@PreAuthorize',
      scope: 'FIELD', phase: 'PRE', field: 'ssn', target: { className: 'x.Employee', method: 'getSsn()' },
      denial: denial && { kind: denial } });
    const m = model([app('a', [location('location:mask', 'HANDLER'), location('location:newer', 'REDIRECT' as DenialKind)])]);
    const guard = (location: string, mechanism: string, requirement: string): ExposureStep =>
      ({ location, mechanism, requirement, guards: 'a/field:x.Employee.ssn' });
    const steps = [guard('a/location:mask', '@PreAuthorize', 'ROLE_ADMIN'), guard('a/location:newer', '@PreAuthorize',
      'ROLE_HR'), guard('a/location:gone', '@Secured', 'ROLE_X'), { location: 'a/location:other', mechanism: '@Secured',
      requirement: 'ROLE_Y' }];
    const plan = lineagePlan(m, [
      response('ssn', [flow('a/field:x.Employee.ssn', 'a/field:x.View.ssn')], { steps }),
      response('name', [flow('a/field:x.Employee.name', 'a/field:x.View.name')], { steps: steps.slice(0, 1) }),
    ], new Set());
    const ssn = rowOf(plan, 'a/field:x.Employee.ssn');
    expect(ssn.guards).toEqual([
      { text: 'ROLE_ADMIN', denial: 'HANDLER', tooltip: '@PreAuthorize requires ROLE_ADMIN; when denied: A custom handler'
        + ' replaces the value, typically with a mask. The request succeeds' },
      { text: 'ROLE_HR', denial: 'REDIRECT', tooltip: '@PreAuthorize requires ROLE_HR; when denied: REDIRECT' },
      { text: 'ROLE_X', denial: undefined, tooltip: '@Secured requires ROLE_X; when denied: ' },
    ]);
    expect(rowHeight(ssn)).toBe(ROW_H + 3 * GUARD_H);
    expect(rowOf(plan, 'a/field:x.Employee.name').guards).toEqual([]);
    // A class with a guarded row is drawn open: its checks are what it has to show.
    expect(boxOf(plan, 'x.Employee').passThrough).toBe(false);
  });

  it('show labels and declassified fields, a JSON name that differs, and the Java type on hover', () => {
    const m = model([app('a', [field('x.Employee', 'ssn', { labels: ['PII'], javaType: 'java.lang.String' }),
      field('x.Employee', 'salary', { declassified: true }), field('x.Dto', 'fullName', { jsonName: 'full_name' }),
      field('x.View', 'name', { jsonName: 'name' })])]);
    const plan = lineagePlan(m, [
      response('ssn', [flow('a/field:x.Employee.ssn', 'a/field:x.View.ssn')]),
      { ...response('pay', [flow('a/field:x.Employee.salary', 'a/field:x.View.salary', 'COMPUTED')]),
        fieldId: 'a/field:x.View.salary' },
      response('name', [flow('a/field:x.Dto.fullName', 'a/field:x.View.name'), flow('a/field:x.Employee.name',
        'a/field:x.Dto.fullName')]),
    ], new Set());
    expect(rowOf(plan, 'a/field:x.Employee.ssn')).toMatchObject({ chips: [{ text: 'PII', tone: 'label' }], note: '',
      tooltip: 'a/field:x.Employee.ssn\nString' });
    expect(rowOf(plan, 'a/field:x.Employee.salary').chips).toEqual([{ text: 'declassified', tone: 'declassified' }]);
    expect(rowOf(plan, 'a/field:x.View.salary').note).toBe('json pay');
    expect(rowOf(plan, 'a/field:x.Dto.fullName')).toMatchObject({ note: 'json full_name', tooltip: 'a/field:x.Dto.fullName' });
    expect(rowOf(plan, 'a/field:x.View.name').note).toBe('');
    expect(rowOf(plan, 'a/field:x.Employee.name').note).toBe('');
  });

  it('read a view\'s field as the model path its template reads, in a box named after the view', () => {
    const plan = lineagePlan(model([app('a', [])]), [{ ...endpoint('a', '/owners/{id}', 'R', 'owner.pets[].name'),
      fieldId: 'a/field:view:owners/details.owner:pets[]:name', lineage: [flow('a/field:x.Pet.name',
        'a/field:view:owners/details.owner:pets[]:name')] }], new Set());
    const view = boxOf(plan, 'view:owners/details');
    expect(view.fields[0]).toMatchObject({ name: 'owner.pets[].name', note: '' });
    expect(boxTitle(view)).toBe('owners/details (view)');
    expect(boxTitle(boxOf(plan, 'x.Pet'))).toBe('Pet');
  });

  it('name a nested class by its innermost name', () => {
    const plan = lineagePlan(model([app('a', [])]), [{ ...response('id', []), fieldId: 'a/field:x.Outer$Inner.id' }],
      new Set());
    expect(boxTitle(plan.boxes[0])).toBe('Inner');
  });
});

describe('lineage arrows', () => {
  it('cross a link thick, dashed until a trace has seen the call', () => {
    const network = (from: string, to: string, egress: string): Flow =>
      ({ path: egress, from, to, source: 'DIRECT', kind: 'NETWORK' });
    const m = model([app('a', []), app('b', [])], [link('a/egress:call', 'b/ingress:GET /x', 'NETWORK_OBSERVED'),
      link('a/egress:guess', 'b/ingress:GET /y')]);
    const plan = lineagePlan(m, [
      response('ssn', [network('b/field:x.Employee.ssn', 'a/field:x.View.ssn', 'a/egress:call')]),
      response('name', [network('b/field:x.Employee.name', 'a/field:x.View.name', 'a/egress:guess')]),
    ], new Set());
    expect(plan.links.map(found => [found.from.name, found.network, found.inferred])).toEqual([['ssn', true, false],
      ['name', true, true]]);
    // Two copies of the same name between the same classes, but one observed and one not: no shared arrow.
    expect(plan.bundles).toEqual([]);
    expect(boxOf(plan, 'x.Employee').service).toBe('b');
  });

  it('are drawn once for a flow two fields share', () => {
    const plan = lineagePlan(model([app('a', [])]), [
      response('name', [flow('a/field:x.Dto.name', 'a/field:x.View.name'), flow('a/field:x.Source.name', 'a/field:x.Dto.name')]),
      response('label', [flow('a/field:x.Dto.name', 'a/field:x.View.label', 'COMPUTED'),
        flow('a/field:x.Source.name', 'a/field:x.Dto.name')]),
    ], new Set());
    expect(plan.links).toHaveLength(3);
    expect(rowOf(plan, 'a/field:x.Dto.name').out).toHaveLength(2);
    // One field copied as is between two classes needs no shared arrow, so nothing collapses.
    expect(plan.bundles).toEqual([]);
    expect(boxOf(plan, 'x.Dto').collapsed).toBe(false);
  });
});

describe('lineage columns', () => {
  it('draw a response class nothing flows into below the one that is fed, and a field with no source last', () => {
    const plan = lineagePlan(model([app('a', [])]), [
      response('id', [flow('a/field:x.Source.id', 'a/field:x.View.id')]),
      { ...response('version', []), fieldId: 'a/field:x.Meta.version' },
      response('constant', []),
    ], new Set());
    const view = boxOf(plan, 'x.View');
    const meta = boxOf(plan, 'x.Meta');
    expect(meta.role).toBe('response');
    expect(meta.x).toBe(view.x);
    expect(meta.y).toBeGreaterThan(view.y + view.height - 1);
    expect(view.fields.map(row => row.name)).toEqual(['id', 'constant']);
    expect(boxOf(plan, 'x.Source').x).toBeLessThan(view.x);
  });

  it('keep a field that feeds another of its class in that class, its arrow inside it', () => {
    const plan = lineagePlan(model([app('a', [])]), [
      response('full', [flow('a/field:x.View.first', 'a/field:x.View.full', 'COMPUTED'),
        flow('a/field:x.Source.first', 'a/field:x.View.first')]),
    ], new Set());
    const inside = plan.links.find(found => found.to.name === 'full')!;
    expect(inside.from.box).toBe(inside.to.box);
    expect(plan.boxes.map(found => found.className)).toEqual(['x.View', 'x.Source']);
    // The fed row sits level with what feeds it; the response row, fed from inside the class, below it.
    expect(boxOf(plan, 'x.View').fields.map(row => row.name)).toEqual(['first', 'full']);
  });

  it('draw one column for a response with no lineage, and nothing for no fields', () => {
    const plan = lineagePlan(model([app('a', [])]), [response('id', []), response('name', [])], new Set());
    expect(plan.boxes).toHaveLength(1);
    expect(plan.boxes[0].fields.map(row => row.name)).toEqual(['id', 'name']);
    expect(plan.width).toBe(2 * 20 + 248);
    expect(lineagePlan(model([app('a', [])]), [], new Set())).toMatchObject({ boxes: [], links: [], bundles: [] });
  });

  it('still end, each class drawn once, when flows go round between classes', () => {
    const plan = lineagePlan(model([app('a', [])]), [
      response('v', [flow('a/field:x.A.x', 'a/field:x.View.v'), flow('a/field:x.B.y', 'a/field:x.A.x'),
        flow('a/field:x.A.w', 'a/field:x.B.y', 'COMPLEX')]),
    ], new Set());
    expect(plan.boxes.map(found => found.className).sort()).toEqual(['x.A', 'x.B', 'x.View']);
    expect(plan.boxes.every(found => Number.isFinite(found.x) && Number.isFinite(found.y))).toBe(true);
    expect(Number.isFinite(plan.width) && Number.isFinite(plan.height)).toBe(true);
  });
});
