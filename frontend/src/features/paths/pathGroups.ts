// @supports PATHS_VIEW
import { endpointText, requirementText } from '@/lib/format';
import { qualify, serviceOf, type Model } from '@/lib/model';
import type { Edge } from '@/lib/types';
import { firstSegment, runsBy } from '@/lib/utils';

/** How deep links are followed into called services. */
const MAX_DEPTH = 4;

/** One step of a request path, before merging: a tree in time order. */
interface TreeStep {
  qid: string;
  service: string;
  edge: Edge | null;
  next: TreeStep | null;
  calls: { link: Edge; to: TreeStep }[];
}

/** A step after merging: shared by every path that reaches it with the same steps after it. */
export interface PathNode {
  id: number;
  qid: string;
  service: string;
  next: PathNode | null;
  calls: { link: Edge; to: PathNode }[];
  /** The local edge that leads to {@link next}. */
  nextEdge: Edge | null;
}

export interface Root {
  ingress: string;
  node: PathNode;
  checks: number;
}

export interface Group {
  roots: Root[];
  nodes: Set<PathNode>;
  /** The same group in other services, drawn once (each one's actuator health, say). */
  twins: Group[];
  key: string;
}

/**
 * One request path as a tree in time order: each step points to the next one, and an egress also to the paths of the
 * services it calls (whose checks run before the caller's next step).
 */
function pathTree(model: Model, ingress: string, follow: boolean, depth = 0, stack: string[] = [ingress]): TreeStep {
  const service = serviceOf(ingress);
  const steps: { qid: string; edge: Edge | null }[] = [{ qid: ingress, edge: null },
    ...model.path(ingress).map(edge => ({ qid: qualify(service, edge.to), edge }))];
  let next: TreeStep | null = null;
  for (let index = steps.length - 1; index >= 0; index--) {
    const { qid, edge } = steps[index];
    const calls = follow && model.node(qid)?.type === 'egress' && depth < MAX_DEPTH
      ? model.linksFrom(qid).filter(link => !stack.includes(link.to))
        .map(link => ({ link, to: pathTree(model, link.to, follow, depth + 1, [...stack, link.to]) }))
      : [];
    next = { qid, service, edge, next, calls };
  }
  return next!;
}

function countChecks(model: Model, step: TreeStep | null): number {
  return !step ? 0 : (model.node(step.qid)?.type === 'location' ? 1 : 0) + countChecks(model, step.next)
    + step.calls.reduce((sum, call) => sum + countChecks(model, call.to), 0);
}

export function reach(node: PathNode | null, seen = new Set<PathNode>()): Set<PathNode> {
  if (node && !seen.has(node)) {
    seen.add(node);
    reach(node.next, seen);
    node.calls.forEach(call => reach(call.to, seen));
  }
  return seen;
}

/**
 * Merges the request paths of these ingresses: two steps become one when they are the same node and everything after
 * them is the same, so every drawn path is a real one. Endpoints that end up sharing a step form one group; endpoints
 * with no step at all share one group per service; the same group in several services is drawn once.
 */
export function mergePaths(model: Model, ingresses: string[], follow: boolean): Group[] {
  const merged = new Map<string, PathNode>();
  const intern = (step: TreeStep): PathNode => {
    const next = step.next && intern(step.next);
    const calls = step.calls.map(call => ({ link: call.link, to: intern(call.to) }));
    const signature = `${step.qid}|${calls.map(call => `${call.link.kind}>${call.to.id}`).join(',')}|${next?.id ?? ''}`
      + (step.next?.edge?.conditional ? '|some branches' : '');
    if (!merged.has(signature)) {
      merged.set(signature, { id: merged.size, qid: step.qid, service: step.service, next, calls,
        nextEdge: step.next?.edge ?? null });
    }
    return merged.get(signature)!;
  };
  const roots: Root[] = ingresses.map(ingress => {
    const tree = pathTree(model, ingress, follow);
    return { ingress, node: intern(tree), checks: countChecks(model, tree) };
  });
  const groupOf = new Map<PathNode, Group>();
  let groups: Group[] = [];
  for (const root of roots) {
    const reached = reach(root.node);
    const group = [...reached].map(node => groupOf.get(node)).find(Boolean)
      ?? { roots: [], nodes: new Set<PathNode>(), twins: [], key: '' };
    if (!group.roots.length) {
      groups.push(group);
    }
    for (const other of new Set([...reached].map(node => groupOf.get(node)).filter(found => found && found !== group))) {
      // A root that bridges two groups joins them.
      other!.roots.forEach(item => group.roots.push(item));
      other!.nodes.forEach(node => { group.nodes.add(node); groupOf.set(node, group); });
      groups = groups.filter(found => found !== other);
    }
    group.roots.push(root);
    reached.forEach(node => { group.nodes.add(node); groupOf.set(node, group); });
  }
  // Endpoints with no step at all (no check, no call) share nothing to draw, but are all alike: one card per service.
  const bare = new Map<string, Group>();
  for (const group of [...groups]) {
    if (group.roots.length === 1 && !group.roots[0].node.next && !group.roots[0].node.calls.length) {
      const service = group.roots[0].node.service;
      const kept = bare.get(service);
      if (kept) {
        group.roots.forEach(root => kept.roots.push(root));
        group.nodes.forEach(node => kept.nodes.add(node));
        groups = groups.filter(found => found !== group);
      }
      else {
        bare.set(service, group);
      }
    }
  }
  const order = (ingress: string) => ingresses.indexOf(ingress);
  for (const group of groups) {
    group.roots.sort((a, b) => order(a.ingress) - order(b.ingress));
  }
  // The same path in several services (each one's actuator health, say): one card, drawn once.
  const byShape = new Map<string, Group>();
  for (const group of [...groups]) {
    const key = shape(model, group);
    const twin = key ? byShape.get(key) : undefined;
    if (twin) {
      twin.twins.push(group);
      groups = groups.filter(found => found !== group);
    }
    else if (key) {
      byShape.set(key, group);
    }
  }
  for (const group of groups) {
    group.key = [group, ...group.twins].flatMap(member => member.roots.map(root => root.ingress)).join(' ');
  }
  return groups.sort((a, b) => order(a.roots[0].ingress) - order(b.roots[0].ingress));
}

/**
 * How a group reads apart from its service: its endpoints, their requirements and each step's kind, mechanism and
 * requirement; null for a group that spans services, which has no twin.
 */
function shape(model: Model, group: Group): string | null {
  if (new Set([...group.nodes].map(node => node.service)).size !== 1) {
    return null;
  }
  const step = (qid: string) => {
    const node = model.node(qid);
    return [node?.type, node?.type === 'location' ? node.mechanism : '',
      node?.type === 'location' && node.requirement ? requirementText(node.requirement) : '',
      node?.type === 'egress' ? `${node.httpMethod} ${node.uriTemplate}` : ''].join(':');
  };
  const steps = (node: PathNode | null): string[] => (node ? [step(node.qid), ...steps(node.next)] : []);
  return group.roots.map(root => {
    const ingress = model.node(root.ingress);
    return [ingress?.type === 'ingress' ? endpointText(ingress) : root.ingress,
      model.endpointExposure(root.ingress)?.requirement ?? '', ...steps(root.node.next)].join(' > ');
  }).join('\n');
}

/** The services a group's card stands for: its own and its twins'. */
export function servicesOf(group: Group): string[] {
  return [group, ...group.twins].map(member => member.roots[0].node.service);
}

/** Whether every endpoint of the group has nothing after it: a list says the same as lone boxes, in less space. */
export function isBare(group: Group): boolean {
  return group.roots.every(root => !root.node.next && !root.node.calls.length);
}

/**
 * Consecutive endpoints that read the same in a card's list: same service, same requirement, same number of checks,
 * the same callers, and the same first path segment (so /actuator stays apart from the application's own).
 */
export function runs(model: Model, roots: Root[]): Root[][] {
  const key = (root: Root) => {
    const exposure = model.endpointExposure(root.ingress);
    const callers = [...new Set(model.linksTo(root.ingress).map(link => serviceOf(link.from)))].join(',');
    const ingress = model.node(root.ingress);
    return [serviceOf(root.ingress), exposure?.requirement ?? '', root.checks, callers,
      firstSegment(ingress?.type === 'ingress' ? ingress.route : '')].join('|');
  };
  return runsBy(roots, key);
}

/** Whether the group's text matches every word of a search: endpoints, services and requirements. */
export function matches(model: Model, group: Group, words: string[]): boolean {
  if (!words.length) {
    return true;
  }
  const text = [group, ...group.twins].flatMap(member => member.roots).map(root => {
    const ingress = model.node(root.ingress);
    return [serviceOf(root.ingress), ingress?.type === 'ingress' ? endpointText(ingress) : '',
      model.endpointExposure(root.ingress)?.requirement ?? ''].join(' ');
  }).join(' ').toLowerCase();
  return words.every(word => text.includes(word));
}
