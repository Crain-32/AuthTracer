// @supports PATHS_VIEW
import { MarkerType, type Edge as FlowEdge, type EdgeMouseHandler } from '@xyflow/react';
import { useMemo } from 'react';

import { ScaledFlow } from '@/components/ScaledFlow';
import { authorityText, count, methodKey } from '@/lib/format';
import type { Model } from '@/lib/model';
import { useUi, type Selection } from '@/lib/store';
import type { Edge } from '@/lib/types';

import { LaneNode, type LaneFlowNode } from './LaneNode';
import type { Group } from './pathGroups';
import { stepPosition, type PathPlan } from './pathLayout';
import { StepNode, type StepFlowNode } from './StepNode';
import { stepSpec } from './stepSpec';

const nodeTypes = { step: StepNode, lane: LaneNode };

type EdgeData = { selection: Selection };

/** An arrow, with where a smoothstep one turns. */
type DiagramEdge = FlowEdge<EdgeData> & { pathOptions?: { stepPosition: number } };

/**
 * A group's request paths: one lane per service, steps left to right in time order. Local steps join with grey
 * arrows (dashed when on some branches only); calls to other services with violet ones.
 */
export function PathDiagram({ model, group, plan }: { model: Model; group: Group; plan: PathPlan }) {
  const selection = useUi(state => state.selection);
  const select = useUi(state => state.select);
  const selectedQid = selection?.type === 'node' ? selection.qid : null;

  const nodes = useMemo<(LaneFlowNode | StepFlowNode)[]>(() => {
    const lanes: LaneFlowNode[] = plan.lanes.map((lane, index) => ({
      id: `lane:${lane.service}`, type: 'lane', position: { x: 4, y: lane.top }, zIndex: -1,
      data: { service: lane.service, width: plan.width - 8, height: lane.height, shade: index % 2 === 1,
        tooltip: authorityText(model.graphs.get(lane.service)?.authoritySource) },
    }));
    const steps: StepFlowNode[] = [...group.nodes].map(node => ({
      id: `n${node.id}`, type: 'step', position: plan.at.get(node)!,
      data: { spec: stepSpec(model, node.qid), selected: node.qid === selectedQid },
    }));
    return [...lanes, ...steps];
  }, [model, group, plan, selectedQid]);

  const edges = useMemo<DiagramEdge[]>(() => {
    const result: DiagramEdge[] = [];
    for (const node of group.nodes) {
      if (node.next && node.nextEdge) {
        const edge = node.nextEdge;
        result.push({
          id: `e${node.id}-${node.next.id}`, source: `n${node.id}`, target: `n${node.next.id}`, type: 'smoothstep',
          pathOptions: { stepPosition: stepPosition(plan.at.get(node)!, plan.at.get(node.next)!) },
          className: 'clickable', ariaLabel: localTitle(edge),
          style: { stroke: 'var(--flow-direct)', strokeWidth: 1.5, strokeDasharray: edge.conditional ? '5 4' : undefined },
          markerEnd: { type: MarkerType.ArrowClosed, color: 'var(--flow-direct)', width: 16, height: 16 },
          data: { selection: { type: 'edge', service: node.service, edge } },
        });
      }
      for (const call of node.calls) {
        const observed = call.link.kind === 'NETWORK_OBSERVED';
        const seen = model.linkObservation(call.link);
        result.push({
          id: `l${node.id}-${call.to.id}`, source: `n${node.id}`, target: `n${call.to.id}`, type: 'default',
          className: 'clickable', ariaLabel: `Network-${observed ? 'observed' : 'inferred'} link`,
          label: observed ? (seen ? count(seen.count, 'call') : 'observed') : 'inferred',
          labelStyle: { fill: 'var(--egress)', fontSize: 11, fontWeight: 600 },
          labelBgStyle: { fill: 'var(--card)' }, labelBgPadding: [4, 2], labelBgBorderRadius: 4,
          style: { stroke: 'var(--egress)', strokeWidth: 2, strokeDasharray: observed ? undefined : '6 4' },
          markerEnd: { type: MarkerType.ArrowClosed, color: 'var(--egress)', width: 16, height: 16 },
          markerStart: call.link.bidirectional ? { type: MarkerType.ArrowClosed, color: 'var(--egress)', width: 14,
            height: 14 } : undefined,
          data: { selection: { type: 'link', link: call.link } },
        });
      }
    }
    return result;
  }, [model, group, plan]);

  const onEdgeClick: EdgeMouseHandler<FlowEdge<EdgeData>> = (_, edge) => edge.data && select(edge.data.selection);
  return <ScaledFlow width={plan.width} height={plan.height} minHeight={120} nodes={nodes} edges={edges}
    nodeTypes={nodeTypes} onEdgeClick={onEdgeClick} />;
}

function localTitle(edge: Edge): string {
  return 'Local call path' + (edge.conditional ? ': on some branches only' : '')
    + (edge.via.length ? `, via ${edge.via.map(methodKey).join(' → ')}` : '');
}
