// @supports PATHS_VIEW
import { reach, type Group, type PathNode, type Root } from './pathGroups';

export const STEP_W = 196;
export const STEP_H = 64;
const COL_GAP = 52;
const ROW_GAP = 18;
const LANE_PAD = 16;
const LANE_HEAD = 30;
const PAD = 16;

export interface Lane {
  service: string;
  top: number;
  height: number;
}

export interface PathPlan {
  at: Map<PathNode, { x: number; y: number }>;
  lanes: Lane[];
  width: number;
  height: number;
}

/**
 * Columns follow time: a step comes after the one before it, and after everything the services called before it do.
 * Rows: each run of new steps takes the first free row of its service's lane, and a run that reaches a step already
 * drawn ends there, with its arrow joining it. Callers' lanes come above the services they call.
 */
export function layout(group: Group): PathPlan {
  const nodes = [...group.nodes];
  const column = new Map(nodes.map(node => [node, 0]));
  for (let round = 0, changed = true; changed && round <= nodes.length; round++) {
    changed = false;
    const extent = new Map<PathNode, number>();
    const last = (node: PathNode | null): number => {
      if (!node) {
        return -1;
      }
      if (!extent.has(node)) {
        extent.set(node, -1);
        extent.set(node, Math.max(column.get(node)!, last(node.next), ...node.calls.map(call => last(call.to))));
      }
      return extent.get(node)!;
    };
    const atLeast = (node: PathNode, value: number) => {
      if (column.get(node)! < value) {
        column.set(node, value);
        changed = true;
      }
    };
    for (const node of nodes) {
      node.calls.forEach(call => atLeast(call.to, column.get(node)! + 1));
      if (node.next) {
        atLeast(node.next, Math.max(column.get(node)!, ...node.calls.map(call => last(call.to))) + 1);
      }
    }
  }
  const services: string[] = [];
  const rows = new Map<string, [number, number][][]>();
  const row = new Map<PathNode, number>();
  const run = (start: PathNode) => {
    const steps: PathNode[] = [];
    for (let node: PathNode | null = start; node && !row.has(node); node = node.next) {
      steps.push(node);
    }
    if (!steps.length) {
      return;
    }
    const service = start.service;
    if (!services.includes(service)) {
      services.push(service);
      rows.set(service, []);
    }
    const from = column.get(steps[0])!;
    // A run that joins a step already drawn keeps its row up to that step: its arrow runs along the row, so no other
    // step may stand in the way and seem to be on its path.
    const joins = steps.at(-1)!.next;
    const to = joins ? column.get(joins)! - 1 : column.get(steps.at(-1)!)!;
    const taken = rows.get(service)!;
    let index = taken.findIndex(used => used.every(([a, b]) => b < from || a > to));
    if (index < 0) {
      index = taken.push([]) - 1;
    }
    taken[index].push([from, to]);
    steps.forEach(node => row.set(node, index));
    steps.forEach(node => node.calls.forEach(call => run(call.to)));
  };
  // An endpoint another one calls is drawn by its caller's run, so the called ones take rows in their callers' order:
  // the arrows between the lanes then run side by side, and their labels don't land on each other where they'd cross.
  const called = new Set(nodes.flatMap(node => node.calls.map(call => call.to)));
  const order = joinOrder(group.roots);
  [...order.filter(root => !called.has(root.node)), ...order.filter(root => called.has(root.node))]
    .forEach(root => run(root.node));
  // Callers above the services they call, so links run downwards; otherwise in order of appearance.
  const callees = new Map(services.map(service => [service, new Set<string>()]));
  nodes.forEach(node => node.calls.forEach(call => {
    if (call.to.service !== node.service) {
      callees.get(node.service)!.add(call.to.service);
    }
  }));
  const ordered: string[] = [];
  const pending = [...services];
  while (pending.length) {
    const next = pending.find(service => pending.every(other => other === service || !callees.get(other)!.has(service)))
      ?? pending[0];
    ordered.push(next);
    pending.splice(pending.indexOf(next), 1);
  }
  const lanes: Lane[] = [];
  let top = PAD;
  for (const service of ordered) {
    const count = rows.get(service)!.length;
    const height = LANE_HEAD + 2 * LANE_PAD + count * STEP_H + (count - 1) * ROW_GAP;
    lanes.push({ service, top, height });
    top += height + PAD / 2;
  }
  const laneTop = new Map(lanes.map(lane => [lane.service, lane.top]));
  const at = new Map(nodes.map(node => [node, {
    x: 2 * PAD + column.get(node)! * (STEP_W + COL_GAP),
    y: laneTop.get(node.service)! + LANE_HEAD + LANE_PAD + row.get(node)! * (STEP_H + ROW_GAP),
  }]));
  const columns = Math.max(...column.values()) + 1;
  return { at, lanes, width: 4 * PAD + columns * (STEP_W + COL_GAP) - COL_GAP, height: top + PAD / 2 };
}

/** How far a smoothstep arrow runs straight out of a step before it can turn (React Flow's default offset). */
const STEP_OFFSET = 20;

/**
 * Where a local arrow from one step to the next turns, as a smoothstep edge's stepPosition: in the gap just before the
 * step it joins. The arrow runs along its own row, which the layout keeps free up to there, and turns where no step
 * stands; for adjacent steps that is halfway, as by default.
 */
export function stepPosition(source: { x: number }, target: { x: number }): number {
  const start = source.x + STEP_W + STEP_OFFSET;
  const end = target.x - STEP_OFFSET;
  return (target.x - COL_GAP / 2 - start) / (end - start);
}

/**
 * Roots that join the same step go next to each other, so their rows are adjacent: the first step each reaches, in
 * time order, that another root reaches too.
 */
function joinOrder(roots: Root[]): Root[] {
  const reachedBy = new Map<PathNode, number>();
  roots.forEach(root => reach(root.node).forEach(node => reachedBy.set(node, (reachedBy.get(node) ?? 0) + 1)));
  const joinOf = (root: Root): PathNode | Root => {
    const visit = (node: PathNode | null): PathNode | null => {
      if (!node) {
        return null;
      }
      if (node !== root.node && reachedBy.get(node)! > 1) {
        return node;
      }
      return node.calls.map(call => visit(call.to)).find(Boolean) ?? visit(node.next);
    };
    return visit(root.node) ?? root;
  };
  const joins = roots.map(joinOf);
  return roots.map((root, index) => ({ root, index, first: joins.indexOf(joins[index]) }))
    .sort((a, b) => a.first - b.first || a.index - b.index).map(item => item.root);
}

/** The endpoints in the order the diagram draws them, top to bottom. */
export function drawOrder(group: Group, plan: PathPlan): Root[] {
  const lanes = plan.lanes.map(lane => lane.service);
  const place = (root: Root) => [lanes.indexOf(root.node.service), plan.at.get(root.node)!.y, plan.at.get(root.node)!.x];
  return [...group.roots].sort((a, b) => {
    const [pa, pb] = [place(a), place(b)];
    return pa[0] - pb[0] || pa[1] - pb[1] || pa[2] - pb[2];
  });
}
