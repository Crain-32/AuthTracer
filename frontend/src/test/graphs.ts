import { Model } from '@/lib/model';
import type { ApplicationGraph, Edge, Exposure, FieldNode, GraphNode, SystemGraph } from '@/lib/types';

/** A tiny graph builder for tests: nodes by id, paths as lists of node ids after the ingress. */
export function app(service: string, nodes: GraphNode[], paths: Record<string, string[]> = {}): ApplicationGraph {
  const edges: Edge[] = Object.entries(paths).flatMap(([ingress, steps]) => steps.map((to, index) => ({
    from: index === 0 ? ingress : steps[index - 1], to, kind: 'LOCAL' as const, path: ingress, order: index + 1, via: [],
    bidirectional: false })));
  return { schemaVersion: 1, service, revision: 'test', nodes, edges, flows: [], findings: [] };
}

export function ingress(route: string, method = 'GET'): GraphNode {
  return { type: 'ingress', id: `ingress:${method} ${route}`, httpMethod: method, route };
}

export function check(id: string, requirement: string[] = ['ROLE_ADMIN']): GraphNode {
  return { type: 'location', id, mechanism: '@PreAuthorize', scope: 'METHOD', phase: 'PRE',
    requirement: { kind: 'ANY_AUTHORITY', authorities: requirement }, target: { className: 'x.Service', method: 'm()' } };
}

export function egress(id: string, uri: string): GraphNode {
  return { type: 'egress', id, client: 'RestClient', httpMethod: 'GET', uriTemplate: uri };
}

export function field(owner: string, name: string, more: Partial<FieldNode> = {}): GraphNode {
  return { type: 'field', id: `field:${owner}.${name}`, owner, name, ...more };
}

/** A call from one service's egress to another's ingress, both qualified. */
export function link(from: string, to: string, kind: Edge['kind'] = 'NETWORK_INFERRED'): Edge {
  return { from, to, kind, order: 0, via: [], bidirectional: true };
}

export function system(services: ApplicationGraph[], links: Edge[] = []): SystemGraph {
  return { schemaVersion: 1, services, links, flows: [], observations: [], identities: [], findings: [] };
}

export function endpoint(service: string, route: string, requirement: string, field = ''): Exposure {
  return { service, ingress: `ingress:GET ${route}`, endpoint: `GET ${route}`, field, fieldId: field ? `field:x.${field}` : '',
    requirement, adds: field ? '' : null, steps: [], sources: [], labels: [], lineage: [] };
}

export function model(services: ApplicationGraph[], links: Edge[] = [], exposures: Exposure[] = []): Model {
  return new Model(system(services, links), exposures, 'test');
}
