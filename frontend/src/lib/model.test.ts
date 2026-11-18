import { describe, expect, it } from 'vitest';

import { app, check, egress, endpoint, field, ingress, link, model, system } from '@/test/graphs';

import { asSystem, kindOf, Model, nodeOf, qualify, serviceOf } from './model';
import type { ApplicationGraph, LocationNode, SystemGraph } from './types';

describe('qualified ids', () => {
  it('split at the first slash, so a route in the node id stays whole', () => {
    const qid = qualify('a', 'ingress:GET /owners/{id}');
    expect(qid).toBe('a/ingress:GET /owners/{id}');
    expect(serviceOf(qid)).toBe('a');
    expect(nodeOf(qid)).toBe('ingress:GET /owners/{id}');
  });
});

describe('documents', () => {
  it('are nothing this UI reads when they are not objects with the lists it knows', () => {
    expect(kindOf(null)).toBeNull();
    expect(kindOf([])).toBeNull();
    expect(kindOf({ services: {} })).toBeNull();
  });

  it('keep a system graph as it is', () => {
    const linked = system([app('a', [])]);
    expect(asSystem(linked)).toBe(linked);
  });
});

describe('Model', () => {
  it('reads a graph that leaves lists out as having none, as the server does', () => {
    const bare = { schemaVersion: 1, service: 'a', revision: 'r', nodes: [ingress('/x')] } as unknown as ApplicationGraph;
    const one = new Model(asSystem(bare), [], 'file');
    expect(one.ingresses('a')).toEqual(['a/ingress:GET /x']);
    expect(one.path('a/ingress:GET /x')).toEqual([]);
    expect(one.findings()).toEqual([]);
    expect(one.system.services[0].flows).toEqual([]);

    const linked = new Model({ schemaVersion: 1, services: [{ service: 'b', revision: 'r' }] } as unknown as SystemGraph,
      [], 'file');
    expect(linked.services).toEqual(['b']);
    expect(linked.observed).toBe(false);
    expect(linked.system.identities).toEqual([]);
    expect(linked.system.flows).toEqual([]);
    expect(linked.stats()).toMatchObject({ services: 1, links: 0, findings: 0 });
  });

  it('orders a request path by its edges\' order, and leaves edges of no path out', () => {
    const graph = app('a', [ingress('/x'), check('location:1'), check('location:2')]);
    graph.edges = [
      { from: 'location:1', to: 'location:2', kind: 'LOCAL', path: 'ingress:GET /x', order: 2, via: [], bidirectional: false },
      { from: 'ingress:GET /x', to: 'location:1', kind: 'LOCAL', path: 'ingress:GET /x', order: 1, via: [], bidirectional: false },
      { from: 'location:2', to: 'location:1', kind: 'LOCAL', order: 3, via: [], bidirectional: false },
    ];
    const m = model([graph]);
    expect(m.path('a/ingress:GET /x').map(edge => edge.to)).toEqual(['location:1', 'location:2']);
    expect(m.path('a/ingress:GET /y')).toEqual([]);
  });

  it('lists a service\'s ingresses by route, then method, and none for a service it doesn\'t have', () => {
    const m = model([app('a', [ingress('/b'), ingress('/a', 'POST'), ingress('/a', 'DELETE'), check('location:x')])]);
    expect(m.ingresses('a')).toEqual(['a/ingress:DELETE /a', 'a/ingress:POST /a', 'a/ingress:GET /b']);
    expect(m.ingresses('nope')).toEqual([]);
    expect(m.node('a/location:x')?.type).toBe('location');
    expect(m.node('a/location:none')).toBeUndefined();
  });

  it('names the calls no request path makes', () => {
    const graph = app('a', [ingress('/x'), egress('egress:on', '/on'), egress('egress:off', '/jwks')],
      { 'ingress:GET /x': ['egress:on'] });
    const m = model([graph]);
    expect(m.offPathEgresses('a')).toEqual(['a/egress:off']);
    expect(m.offPathEgresses('nope')).toEqual([]);
  });

  it('looks links up from both ends, with what the traces saw of them', () => {
    const observed = link('a/egress:call', 'b/ingress:GET /x', 'NETWORK_OBSERVED');
    const inferred = link('a/egress:guess', 'b/ingress:GET /x');
    const linked = system([app('a', [egress('egress:call', '/x'), egress('egress:guess', '/x')]), app('b', [ingress('/x')])],
      [observed, inferred]);
    linked.observations = [
      { subject: 'a/egress:call -> b/ingress:GET /x', kind: 'LINK', count: 5, granted: 0, denied: 0 },
      { subject: 'b/location:check', kind: 'LOCATION', count: 3, granted: 2, denied: 1 },
    ];
    const m = new Model(linked, [], 'test');
    expect(m.linksFrom('a/egress:call')).toEqual([observed]);
    expect(m.linksTo('b/ingress:GET /x')).toEqual([observed, inferred]);
    expect(m.linksFrom('b/ingress:GET /x')).toEqual([]);
    expect(m.linksTo('a/egress:call')).toEqual([]);
    expect(m.linkObservation(observed)?.count).toBe(5);
    expect(m.linkObservation(inferred)).toBeUndefined();
    expect(m.observation('b/location:check')?.denied).toBe(1);
    expect(m.observedLink('a/egress:call')).toBe(true);
    expect(m.observedLink('a/egress:guess')).toBe(false);
    expect(m.observedLink(undefined)).toBe(false);
    expect(m.observed).toBe(true);
  });

  it('has observed nothing when the traces held calls but no check decisions', () => {
    const linked = system([app('a', [])]);
    linked.observations = [{ subject: 'a/egress:x -> b/ingress:GET /x', kind: 'LINK', count: 1, granted: 0, denied: 0 }];
    expect(new Model(linked, [], 'test').observed).toBe(false);
  });

  it('finds an endpoint\'s own exposure among its fields\'', () => {
    const exposures = [endpoint('a', '/p', 'ROLE_A', 'name'), endpoint('a', '/p', 'ROLE_A'), endpoint('b', '/p', 'none')];
    const m = model([app('a', [ingress('/p')]), app('b', [ingress('/p')])], [], exposures);
    expect(m.exposuresOf('a', 'ingress:GET /p')).toHaveLength(2);
    expect(m.endpointExposure('a/ingress:GET /p')).toBe(exposures[1]);
    expect(m.endpointExposure('b/ingress:GET /p')?.requirement).toBe('none');
    expect(m.endpointExposure('a/ingress:GET /q')).toBeUndefined();
  });

  it('lists every finding with its service, and the linker\'s as the system\'s', () => {
    const graph = app('a', []);
    graph.findings = [{ kind: 'BYPASSED', message: 'skipped' }];
    const linked = system([graph]);
    linked.findings = [{ kind: 'UNMATCHED_CALL', message: 'no route' }];
    expect(new Model(linked, [], 'test').findings()).toEqual([
      { service: 'a', kind: 'BYPASSED', message: 'skipped' },
      { service: 'system (linker)', kind: 'UNMATCHED_CALL', message: 'no route' },
    ]);
  });

  it('finds the field checks that guard a field: on its getter, or on a GraphQL type\'s field', () => {
    const getter: LocationNode = { type: 'location', id: 'location:getter', mechanism: '@PreAuthorize', scope: 'FIELD',
      phase: 'PRE', target: { className: 'x.Employee', method: 'getSsn()' }, field: 'ssn' };
    const resolver: LocationNode = { ...getter, id: 'location:resolver', target: { className: 'x.EmployeeResolver' },
      fieldOwner: 'x.Employee', field: 'salary' };
    const method: LocationNode = { ...getter, id: 'location:method', scope: 'METHOD' };
    const m = model([app('a', [field('x.Employee', 'ssn'), field('x.Employee', 'salary'), getter, resolver, method])]);
    expect(m.guardsOf('a/field:x.Employee.ssn')).toEqual(['a/location:getter']);
    expect(m.guardsOf('a/field:x.Employee.salary')).toEqual(['a/location:resolver']);
    expect(m.guardsOf('a/field:x.Employee.name')).toEqual([]);
    expect(m.guardsOf('nope/field:x.Employee.ssn')).toEqual([]);
  });

  it('counts the headline numbers: endpoints, the open ones, links, the observed ones, findings', () => {
    const graph = app('a', [ingress('/open'), ingress('/closed')]);
    graph.findings = [{ kind: 'BYPASSED', message: 'm' }];
    const links = [link('b/egress:x', 'a/ingress:GET /open', 'NETWORK_OBSERVED'), link('b/egress:y', 'a/ingress:GET /closed')];
    const m = model([graph, app('b', [])], links,
      [endpoint('a', '/open', 'none'), endpoint('a', '/open', 'none', 'name'), endpoint('a', '/closed', 'ROLE_A')]);
    expect(m.stats()).toEqual({ services: 2, endpoints: 2, open: 1, links: 2, observed: 1, findings: 1 });
  });
});
