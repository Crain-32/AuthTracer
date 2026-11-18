// @supports UI
import type { ApplicationGraph, Edge, Exposure, Finding, GraphNode, LocationNode, Observation, SystemGraph } from './types';
import { groupBy } from './utils';

export function qualify(service: string, nodeId: string): string {
  return `${service}/${nodeId}`;
}

export function serviceOf(qualifiedId: string): string {
  return qualifiedId.slice(0, qualifiedId.indexOf('/'));
}

export function nodeOf(qualifiedId: string): string {
  return qualifiedId.slice(qualifiedId.indexOf('/') + 1);
}

export type DocumentKind = 'system' | 'application' | 'diff';

/** What a loaded JSON document is, or null. */
export function kindOf(json: unknown): DocumentKind | null {
  const value = json as Record<string, unknown> | null;
  if (value && Array.isArray(value.services)) {
    return 'system';
  }
  if (value && Array.isArray(value.nodes)) {
    return 'application';
  }
  if (value && Array.isArray(value.changes)) {
    return 'diff';
  }
  return null;
}

/** A system graph as is, an application graph as a system of one service. */
export function asSystem(json: SystemGraph | ApplicationGraph): SystemGraph {
  if (kindOf(json) === 'system') {
    return json as SystemGraph;
  }
  const graph = json as ApplicationGraph;
  return { schemaVersion: graph.schemaVersion, services: [graph], links: [], flows: [], observations: [],
    identities: [], findings: [] };
}

/** Tolerant on read, as the server is: a graph (an older version's, or hand-written) that leaves a list out has none. */
function complete(system: SystemGraph): SystemGraph {
  return { ...system,
    services: system.services.map(graph => ({ ...graph, nodes: graph.nodes ?? [], edges: graph.edges ?? [],
      flows: graph.flows ?? [], findings: graph.findings ?? [] })),
    links: system.links ?? [], flows: system.flows ?? [], observations: system.observations ?? [],
    identities: system.identities ?? [], findings: system.findings ?? [] };
}

export interface ServiceFinding extends Finding {
  service: string;
}

/**
 * A loaded system graph with lookups by qualified id ("service/nodeId"), plus the exposures the server computed.
 */
export class Model {

  readonly system: SystemGraph;
  readonly graphs: Map<string, ApplicationGraph>;
  readonly links: Edge[];
  /** Whether the traces the link read had any check decisions. */
  readonly observed: boolean;
  private readonly nodes = new Map<string, GraphNode>();
  private readonly paths = new Map<string, Edge[]>();
  private readonly observations: Map<string, Observation>;
  // Views look these up once per row, so they are indexed once here rather than scanned per call.
  private readonly outgoing: Map<string, Edge[]>;
  private readonly incoming: Map<string, Edge[]>;
  private readonly byIngress: Map<string, Exposure[]>;
  private readonly allFindings: ServiceFinding[];

  constructor(loaded: SystemGraph, readonly exposures: Exposure[], readonly origin: string) {
    const system = complete(loaded);
    this.system = system;
    this.graphs = new Map(system.services.map(graph => [graph.service, graph]));
    for (const graph of system.services) {
      for (const node of graph.nodes) {
        this.nodes.set(qualify(graph.service, node.id), node);
      }
      for (const edge of graph.edges) {
        if (edge.path) {
          const key = qualify(graph.service, edge.path);
          const edges = this.paths.get(key) ?? [];
          edges.push(edge);
          this.paths.set(key, edges);
        }
      }
    }
    for (const edges of this.paths.values()) {
      edges.sort((a, b) => a.order - b.order);
    }
    this.links = system.links;
    this.observations = new Map(system.observations.map(observation => [observation.subject, observation]));
    this.observed = system.observations.some(observation => observation.kind === 'LOCATION');
    this.outgoing = groupBy(this.links, link => link.from);
    this.incoming = groupBy(this.links, link => link.to);
    this.byIngress = groupBy(exposures, exposure => qualify(exposure.service, exposure.ingress));
    this.allFindings = [
      ...system.services.flatMap(graph => graph.findings.map(finding => ({ service: graph.service, ...finding }))),
      ...system.findings.map(finding => ({ service: 'system (linker)', ...finding })),
    ];
  }

  get services(): string[] {
    return [...this.graphs.keys()];
  }

  node(qualifiedId: string): GraphNode | undefined {
    return this.nodes.get(qualifiedId);
  }

  /** The ordered edges of one Ingress's request path. */
  path(qualifiedIngressId: string): Edge[] {
    return this.paths.get(qualifiedIngressId) ?? [];
  }

  ingresses(service: string): string[] {
    return (this.graphs.get(service)?.nodes ?? []).filter(node => node.type === 'ingress')
      .sort((a, b) => a.route.localeCompare(b.route) || a.httpMethod.localeCompare(b.httpMethod))
      .map(node => qualify(service, node.id));
  }

  /**
   * A service's calls that no request path makes: a resource server checking tokens with its authorization server,
   * a config or Eureka client (decisions 0049, 0058).
   */
  offPathEgresses(service: string): string[] {
    const graph = this.graphs.get(service);
    if (!graph) {
      return [];
    }
    const onPath = new Set(graph.edges.map(edge => edge.to));
    return graph.nodes.filter(node => node.type === 'egress' && !onPath.has(node.id))
      .map(node => qualify(service, node.id));
  }

  linksFrom(qualifiedId: string): Edge[] {
    return this.outgoing.get(qualifiedId) ?? [];
  }

  linksTo(qualifiedId: string): Edge[] {
    return this.incoming.get(qualifiedId) ?? [];
  }

  observation(qualifiedId: string): Observation | undefined {
    return this.observations.get(qualifiedId);
  }

  linkObservation(link: Edge): Observation | undefined {
    return this.observations.get(`${link.from} -> ${link.to}`);
  }

  /** Whether a trace confirmed a link leaving this egress. */
  observedLink(egressId: string | undefined): boolean {
    return !!egressId && this.linksFrom(egressId).some(link => link.kind === 'NETWORK_OBSERVED');
  }

  exposuresOf(service: string, ingressId: string): Exposure[] {
    return this.byIngress.get(qualify(service, ingressId)) ?? [];
  }

  endpointExposure(qualifiedIngressId: string): Exposure | undefined {
    return this.exposuresOf(serviceOf(qualifiedIngressId), nodeOf(qualifiedIngressId))
      .find(exposure => exposure.field === '');
  }

  /** Every finding, each with the service it belongs to ('system (linker)' for the linker's). */
  findings(): ServiceFinding[] {
    return this.allFindings;
  }

  /** Field-level checks that guard a field: Locations whose target class and field name are the field's. */
  guardsOf(qualifiedFieldId: string): string[] {
    const service = serviceOf(qualifiedFieldId);
    return (this.graphs.get(service)?.nodes ?? []).filter((node): node is LocationNode => node.type === 'location'
      && node.scope === 'FIELD' && `field:${node.fieldOwner ?? node.target.className}.${node.field}` === nodeOf(qualifiedFieldId))
      .map(node => qualify(service, node.id));
  }

  /** The headline numbers: for the top bar. */
  stats() {
    const exposed = this.exposures.filter(exposure => exposure.field === '');
    return {
      services: this.system.services.length,
      endpoints: exposed.length,
      open: exposed.filter(exposure => exposure.requirement === 'none').length,
      links: this.links.length,
      observed: this.links.filter(link => link.kind === 'NETWORK_OBSERVED').length,
      findings: this.findings().length,
    };
  }
}
