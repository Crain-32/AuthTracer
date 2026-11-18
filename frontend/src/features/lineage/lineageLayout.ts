// @supports LINEAGE_VIEW, LEGEND_VIEW
import { DENIALS, shortClass } from '@/lib/format';
import { serviceOf, type Model } from '@/lib/model';
import type { Exposure, Flow } from '@/lib/types';

export const BOX_W = 248;
const COL_GAP = 140;
const BOX_GAP = 28;
const PAD = 20;
export const HEAD_H = 44;
export const ROW_H = 28;
export const GUARD_H = 22;

export interface Guard {
  text: string;
  denial?: string;
  tooltip: string;
}

export interface FieldItem {
  qid: string;
  boxKey: string;
  name: string;
  in: FlowLink[];
  out: FlowLink[];
  response?: Exposure;
  index?: number;
  box?: Box;
  guards: Guard[];
  /** What the row shows besides its name. */
  note: string;
  chips: { text: string; tone: 'label' | 'declassified' }[];
  tooltip: string;
  wanted: number;
  offset: number;
}

export interface FlowLink {
  flow: Flow;
  from: FieldItem;
  to: FieldItem;
  network: boolean;
  inferred: boolean;
  bundle?: Bundle;
}

export interface Bundle {
  id: string;
  from: Box;
  to: Box;
  network: boolean;
  inferred: boolean;
  links: FlowLink[];
}

export interface Box {
  key: string;
  service: string;
  className: string;
  fields: FieldItem[];
  depth: number;
  column: number;
  x: number;
  y: number;
  height: number;
  role: 'response' | 'source' | '';
  passThrough: boolean;
  collapsed: boolean;
}

export interface LineagePlan {
  boxes: Box[];
  links: FlowLink[];
  bundles: Bundle[];
  width: number;
  height: number;
}

export function rowHeight(field: Pick<FieldItem, 'guards'>): number {
  return ROW_H + field.guards.length * GUARD_H;
}

export function boxHeight(box: Pick<Box, 'collapsed' | 'fields'>): number {
  return HEAD_H + (box.collapsed ? ROW_H : box.fields.reduce((sum, field) => sum + rowHeight(field), 0)) + 4;
}

/**
 * Where a field's arrows attach, relative to its box's top: the middle of its row. (A folded box has only shared
 * arrows, which attach to its middle.)
 */
export function anchorOffset(field: FieldItem): number {
  return field.offset + ROW_H / 2;
}

/**
 * Where an endpoint's response fields come from: one box per class with a row per field, sources on the left, the
 * response on the right. Fields copied unchanged between two classes share one arrow, so the arrows that remain are
 * the differences: renames, computed and complex values, and field checks on the rows.
 */
export function lineagePlan(model: Model, exposures: Exposure[], expanded: Set<string>): LineagePlan {
  const { fields, links } = graphOf(model, exposures);
  const boxes = boxesOf(fields, links);
  const bundles = bundlesOf(links);
  for (const field of fields.values()) {
    field.guards = guardsOf(model, exposures, field.qid);
    describe(model, field);
  }
  for (const box of boxes.values()) {
    // A class whose every field is copied in and out unchanged, with nothing to show on its rows, is one line.
    box.passThrough = box.fields.every(field => !field.response && field.in.length && field.out.length
      && [...field.in, ...field.out].every(link => link.bundle) && !field.guards.length && !field.chips.length);
    box.collapsed = box.passThrough && !expanded.has(box.key);
    box.role = box.fields.some(field => field.response) ? 'response'
      : box.fields.every(field => !field.in.length) ? 'source' : '';
  }
  const columns: Box[][] = [];
  const maxDepth = Math.max(0, ...[...boxes.values()].map(box => box.depth));
  for (const box of boxes.values()) {
    (columns[maxDepth - box.depth] ??= []).push(box);
  }
  const place = (column: number, by: Arrangement) => {
    const placed = (columns[column] ?? []).map(box => ({ box, ...arrange(box, by) })).sort((a, b) => a.key - b.key);
    let next = PAD;
    for (const { box, top } of placed) {
      box.column = column;
      box.x = PAD + column * (BOX_W + COL_GAP);
      box.y = Number.isFinite(top) ? Math.max(next, top) : next;
      next = box.y + box.height + BOX_GAP;
    }
  };
  // Right to left, each row level with what it feeds; then the response once more, level with what feeds it, and the
  // rest again. Rows and classes are reordered freely to keep lines from crossing.
  (columns[maxDepth] ?? []).forEach(box => { box.column = maxDepth; });
  place(maxDepth, 'index');
  for (let round = 0; round < (maxDepth > 0 ? 2 : 1); round++) {
    if (round > 0) {
      place(maxDepth, 'sources');
    }
    for (let column = maxDepth - 1; column >= 0; column--) {
      (columns[column] ?? []).forEach(box => { box.column = column; });
      place(column, 'targets');
    }
  }
  const all = [...boxes.values()];
  const bottom = Math.max(0, ...all.map(box => box.y + box.height)) + BOX_GAP;
  return { boxes: all, links, bundles, width: 2 * PAD + (maxDepth + 1) * (BOX_W + COL_GAP) - COL_GAP,
    height: bottom + PAD };
}

/** Fields and the flows between them, each flow once. A field's box is its class. */
function graphOf(model: Model, exposures: Exposure[]) {
  const fields = new Map<string, FieldItem>();
  const links = new Map<string, FlowLink>();
  const add = (qid: string): FieldItem => {
    let field = fields.get(qid);
    if (!field) {
      field = { qid, boxKey: qid.slice(0, qid.lastIndexOf('.')), name: qid.slice(qid.lastIndexOf('.') + 1), in: [],
        out: [], guards: [], note: '', chips: [], tooltip: qid, wanted: Infinity, offset: 0 };
      fields.set(qid, field);
    }
    return field;
  };
  exposures.forEach((exposure, index) => Object.assign(add(exposure.fieldId), { response: exposure, index }));
  for (const flow of exposures.flatMap(exposure => exposure.lineage)) {
    const id = `${flow.from}|${flow.to}`;
    if (!links.has(id)) {
      const network = flow.kind === 'NETWORK';
      const link: FlowLink = { flow, from: add(flow.from), to: add(flow.to), network,
        inferred: network && !model.observedLink(flow.path) };
      links.set(id, link);
      link.from.out.push(link);
      link.to.in.push(link);
    }
  }
  return { fields, links: [...links.values()] };
}

/** One box per class; depth is the longest distance, in classes, to the response. */
function boxesOf(fields: Map<string, FieldItem>, links: FlowLink[]): Map<string, Box> {
  const boxes = new Map<string, Box>();
  for (const field of fields.values()) {
    let box = boxes.get(field.boxKey);
    if (!box) {
      box = { key: field.boxKey, service: serviceOf(field.qid), className: field.boxKey.slice(field.boxKey.indexOf(':') + 1),
        fields: [], depth: 0, column: 0, x: 0, y: 0, height: 0, role: '', passThrough: false, collapsed: false };
      boxes.set(field.boxKey, box);
    }
    field.box = box;
    box.fields.push(field);
  }
  const between = links.filter(link => link.from.box !== link.to.box);
  for (let round = 0, changed = true; changed && round <= boxes.size; round++) {
    changed = false;
    for (const { from, to } of between) {
      if (to.box!.depth + 1 > from.box!.depth) {
        from.box!.depth = to.box!.depth + 1;
        changed = true;
      }
    }
  }
  return boxes;
}

/** Fields copied unchanged (direct, same name) from one class to another, two or more, share one arrow. */
function bundlesOf(links: FlowLink[]): Bundle[] {
  const bundles = new Map<string, Bundle>();
  for (const link of links) {
    if (link.flow.source === 'DIRECT' && link.from.name === link.to.name && link.from.box !== link.to.box) {
      const id = [link.from.box!.key, link.to.box!.key, link.network, link.inferred].join('|');
      let bundle = bundles.get(id);
      if (!bundle) {
        bundle = { id, from: link.from.box!, to: link.to.box!, network: link.network, inferred: link.inferred, links: [] };
        bundles.set(id, bundle);
      }
      bundle.links.push(link);
    }
  }
  const shared = [...bundles.values()].filter(bundle => bundle.links.length > 1);
  shared.forEach(bundle => bundle.links.forEach(link => { link.bundle = bundle; }));
  return shared;
}

type Arrangement = 'index' | 'targets' | 'sources';

/**
 * Orders a box's rows by the response order ('index'), or level with the rows they flow into ('targets') or come from
 * ('sources'); sets the box's height and returns a sort key and where its top would ideally be.
 */
function arrange(box: Box, by: Arrangement): { key: number; top: number } {
  for (const field of box.fields) {
    if (by === 'index') {
      field.wanted = field.response ? field.index! : Infinity;
      continue;
    }
    const ends = by === 'targets'
      ? field.out.filter(link => link.to.box!.column > box.column).map(link => slotY(link.to))
      : field.in.filter(link => link.from.box!.column < box.column).map(link => slotY(link.from));
    // A field that feeds several rows sits by the highest, so a nested class further down does not pull it away.
    field.wanted = !ends.length ? Infinity
      : by === 'targets' ? Math.min(...ends) : ends.reduce((sum, y) => sum + y, 0) / ends.length;
  }
  box.fields.sort((a, b) => a.wanted - b.wanted);
  let offset = HEAD_H;
  for (const field of box.fields) {
    field.offset = offset;
    offset += rowHeight(field);
  }
  box.height = boxHeight(box);
  if (by === 'index') {
    return { key: Math.min(...box.fields.map(field => field.wanted)), top: NaN };
  }
  const known = box.fields.filter(field => Number.isFinite(field.wanted));
  const top = known.length
    ? known.reduce((sum, field) => sum + field.wanted - field.offset - ROW_H / 2, 0) / known.length : NaN;
  return { key: Number.isFinite(top) ? top : Infinity, top };
}

/** Where a row is, or would be in a collapsed box: rows line up through a chain of unchanged copies. */
function slotY(field: FieldItem): number {
  return field.box!.y + field.offset + ROW_H / 2;
}

function guardsOf(model: Model, exposures: Exposure[], qid: string): Guard[] {
  const steps = new Map<string, Exposure['steps'][number]>();
  for (const step of exposures.flatMap(exposure => exposure.steps)) {
    if (step.guards === qid) {
      steps.set(step.location, step);
    }
  }
  return [...steps.values()].map(step => {
    const node = model.node(step.location);
    const denial = node?.type === 'location' ? node.denial?.kind : undefined;
    return { text: step.requirement, denial,
      tooltip: `${step.mechanism} requires ${step.requirement}; when denied: ${denial ? DENIALS[denial]?.title ?? denial : ''}` };
  });
}

function describe(model: Model, field: FieldItem) {
  const node = model.node(field.qid);
  const fieldNode = node?.type === 'field' ? node : undefined;
  field.chips = (fieldNode?.labels ?? []).map(text => ({ text, tone: 'label' as const }));
  if (fieldNode?.declassified) {
    field.chips.push({ text: 'declassified', tone: 'declassified' });
  }
  // The JSON name only when it differs from the Java name; the type is in the tooltip. A view's field is the model
  // path its template reads (owner:pets[]:name is owner.pets[].name).
  if (field.boxKey.includes('field:view:')) {
    field.name = field.name.replaceAll(':', '.');
  }
  const json = field.response ? field.response.field : fieldNode?.jsonName;
  field.note = json && json !== field.name ? `json ${json}` : '';
  field.tooltip = `${field.qid}${fieldNode?.javaType ? `\n${shortClass(fieldNode.javaType)}` : ''}`;
}

/** The title a class box shows: the short class name, or a view's template. */
export function boxTitle(box: Box): string {
  return box.className.startsWith('view:') ? `${box.className.slice('view:'.length)} (view)`
    : shortClass(box.className).split('.').at(-1)!;
}
