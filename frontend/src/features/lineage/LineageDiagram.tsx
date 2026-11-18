// @supports LINEAGE_VIEW
import { MarkerType, type Edge as FlowEdge, type EdgeMouseHandler } from '@xyflow/react';
import { useMemo } from 'react';

import { ScaledFlow } from '@/components/ScaledFlow';
import { FIELD_SOURCES } from '@/lib/format';
import type { Model } from '@/lib/model';
import { useUi } from '@/lib/store';
import type { Exposure, Flow } from '@/lib/types';
import { groupBy } from '@/lib/utils';

import { anchorOffset, boxTitle, lineagePlan, type Bundle, type FlowLink } from './lineageLayout';
import { BundleEdge, type BundleFlowEdge } from './BundleEdge';
import { RecordNode, type ExtraHandle, type RecordFlowNode } from './RecordNode';

const nodeTypes = { record: RecordNode };
const edgeTypes = { bundle: BundleEdge };

const FLOW_COLORS: Record<Flow['source'], string> = {
  DIRECT: 'var(--flow-direct)',
  COMPLEX: 'var(--flow-complex)',
  COMPUTED: 'var(--flow-computed)',
  MASKED: 'var(--flow-masked)',
};

type FlowLinkEdge = FlowEdge<{ flow: Flow }, 'default' | 'smoothstep'>;

/** Where an endpoint's response fields come from: classes as boxes, flows as arrows between their rows. */
export function LineageDiagram({ model, exposures }: { model: Model; exposures: Exposure[] }) {
  const expanded = useUi(state => state.lineage.expanded);
  const setLineage = useUi(state => state.setLineage);
  const selection = useUi(state => state.selection);
  const select = useUi(state => state.select);
  const selectedQid = selection?.type === 'node' ? selection.qid : null;
  const plan = useMemo(() => lineagePlan(model, exposures, expanded), [model, exposures, expanded]);

  const nodes = useMemo<RecordFlowNode[]>(() => {
    const extra = groupBy(plan.bundles.flatMap(bundle => [
      { key: bundle.from.key, handle: { id: `bundle-out:${bundle.id}`, type: 'source', top: bundleSide(bundle, 'from') } },
      { key: bundle.to.key, handle: { id: `bundle-in:${bundle.id}`, type: 'target', top: bundleSide(bundle, 'to') } },
    ] satisfies { key: string; handle: ExtraHandle }[]), entry => entry.key);
    return plan.boxes.map(box => ({
      id: box.key, type: 'record', position: { x: box.x, y: box.y }, draggable: false,
      data: {
        box, title: boxTitle(box), shade: Math.max(0, model.services.indexOf(box.service)),
        extraHandles: (extra.get(box.key) ?? []).map(entry => entry.handle), selectedQid,
        onSelectField: (qid: string) => select({ type: 'node', qid }),
        onToggle: box.passThrough ? () => {
          const next = new Set(expanded);
          if (next.has(box.key)) {
            next.delete(box.key);
          }
          else {
            next.add(box.key);
          }
          setLineage({ expanded: next });
        } : undefined,
      },
    }));
  }, [plan, model, selectedQid, expanded, select, setLineage]);

  const edges = useMemo<(BundleFlowEdge | FlowLinkEdge)[]>(() => {
    const result: (BundleFlowEdge | FlowLinkEdge)[] = plan.bundles.map(bundle => ({
      id: `bundle:${bundle.id}`, type: 'bundle', source: bundle.from.key, target: bundle.to.key,
      sourceHandle: `bundle-out:${bundle.id}`, targetHandle: `bundle-in:${bundle.id}`,
      ariaLabel: `${bundle.links.length} fields copied as is`,
      data: { label: `${bundle.links.length} fields as is`, fields: bundle.links.map(link => link.from.name) },
      style: { stroke: FLOW_COLORS.DIRECT, strokeWidth: bundle.network ? 4 : 3, opacity: 0.75,
        strokeDasharray: bundle.inferred ? '7 5' : undefined },
      markerEnd: { type: MarkerType.ArrowClosed, color: FLOW_COLORS.DIRECT, width: 14, height: 14 },
    }));
    const labelled = new Set<string>();
    for (const link of plan.links.filter(found => !found.bundle)) {
      // Several computed inputs of one field need one label, not one each.
      const id = `${link.to.qid}|${link.flow.source}`;
      result.push(flowEdge(link, !labelled.has(id)));
      labelled.add(id);
    }
    return result;
  }, [plan]);

  const onEdgeClick: EdgeMouseHandler<BundleFlowEdge | FlowLinkEdge> = (_, edge) => edge.data && 'flow' in edge.data
    && select({ type: 'flow', flow: edge.data.flow });
  return <ScaledFlow width={plan.width} height={plan.height} minHeight={160} nodes={nodes} edges={edges}
    nodeTypes={nodeTypes} edgeTypes={edgeTypes} onEdgeClick={onEdgeClick} />;
}

/** A bundle's arrow leaves and enters level with the middle of its rows. */
function bundleSide(bundle: Bundle, side: 'from' | 'to'): number {
  const box = side === 'from' ? bundle.from : bundle.to;
  if (box.collapsed) {
    return box.height / 2;
  }
  const fields = bundle.links.map(link => link[side]);
  return fields.reduce((sum, field) => sum + anchorOffset(field), 0) / fields.length;
}

function flowEdge(link: FlowLink, labelled: boolean): FlowLinkEdge {
  const { flow, from, to } = link;
  const color = FLOW_COLORS[flow.source];
  // Direct is the usual case and network flows are drawn thick: only computed and complex flows get a label.
  const label = flow.source === 'DIRECT' || !labelled ? undefined : flow.source.toLowerCase();
  return {
    // A folded class's links all share arrows, so a flow of its own always attaches to a row.
    id: `flow:${flow.from}|${flow.to}`, source: from.box!.key, target: to.box!.key,
    sourceHandle: `out:${from.qid}`, targetHandle: `in:${to.qid}`,
    className: 'clickable', label, type: from.box === to.box ? 'smoothstep' : 'default',
    ariaLabel: `${FIELD_SOURCES[flow.source]}${link.network ? `, across a ${link.inferred ? 'network-inferred'
      : 'network-observed'} link` : ''}`,
    labelStyle: { fill: color, fontSize: 11, fontWeight: 600 }, labelBgStyle: { fill: 'var(--card)' },
    labelBgPadding: [4, 2], labelBgBorderRadius: 4,
    style: { stroke: color, strokeWidth: link.network ? 3.5 : 1.75, strokeDasharray: link.inferred ? '7 5' : undefined },
    markerEnd: { type: MarkerType.ArrowClosed, color, width: 14, height: 14 },
    data: { flow },
  };
}
