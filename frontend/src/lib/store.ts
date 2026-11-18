// @supports UI
import { create } from 'zustand';

import type { Model } from './model';
import type { DiffReport, Edge, Exposure, Flow } from './types';

export type ViewId = 'paths' | 'lineage' | 'exposures' | 'findings' | 'identities' | 'diff' | 'legend';

/** What the details panel shows: a node, a local edge, a network link, a field flow, or an exposure row. */
export type Selection =
  | { type: 'node'; qid: string }
  | { type: 'edge'; service: string; edge: Edge }
  | { type: 'link'; link: Edge }
  | { type: 'flow'; flow: Flow }
  | { type: 'exposure'; exposure: Exposure };

export interface Status {
  text: string;
  error?: boolean;
  busy?: boolean;
}

interface PathsState {
  service: string;
  follow: boolean;
  open: Set<string>;
  search: string;
}

interface LineageState {
  endpoint: string | null;
  field: string;
  expanded: Set<string>;
}

interface ExposuresState {
  filter: string;
  expanded: Set<string>;
}

interface UiState {
  model: Model | null;
  diff: { report: DiffReport; name: string } | null;
  view: ViewId;
  selection: Selection | null;
  status: Status;
  paths: PathsState;
  lineage: LineageState;
  exposures: ExposuresState;
  loadModel(model: Model): void;
  loadDiff(report: DiffReport, name: string): void;
  show(view: ViewId): void;
  select(selection: Selection | null): void;
  setStatus(status: Status): void;
  setPaths(change: Partial<PathsState>): void;
  setLineage(change: Partial<LineageState>): void;
  setExposures(change: Partial<ExposuresState>): void;
  /** Opens the lineage view on one endpoint, and optionally one of its fields. */
  showLineage(service: string, ingress: string, field?: string): void;
}

const initialPaths = (): PathsState => ({ service: '', follow: true, open: new Set(), search: '' });
const initialLineage = (): LineageState => ({ endpoint: null, field: '', expanded: new Set() });
const initialExposures = (): ExposuresState => ({ filter: '', expanded: new Set() });

export const useUi = create<UiState>(set => ({
  model: null,
  diff: null,
  view: 'paths',
  selection: null,
  status: { text: 'Loading…', busy: true },
  paths: initialPaths(),
  lineage: initialLineage(),
  exposures: initialExposures(),
  loadModel: model => set({ model, selection: null, paths: initialPaths(), lineage: initialLineage(),
    exposures: initialExposures(), status: { text: model.origin } }),
  loadDiff: (report, name) => set({ diff: { report, name }, view: 'diff', selection: null }),
  // Details belong to the view they were opened in.
  show: view => set(state => state.view === view ? {} : { view, selection: null }),
  select: selection => set({ selection }),
  setStatus: status => set({ status }),
  setPaths: change => set(state => ({ paths: { ...state.paths, ...change } })),
  setLineage: change => set(state => ({ lineage: { ...state.lineage, ...change } })),
  setExposures: change => set(state => ({ exposures: { ...state.exposures, ...change } })),
  // Unlike show(), this keeps the selection: the exposure in the details panel is the one whose lineage opens.
  showLineage: (service, ingress, field) => set(state => ({
    view: 'lineage', lineage: { ...state.lineage, endpoint: `${service}|${ingress}`, field: field ?? '' },
  })),
}));
