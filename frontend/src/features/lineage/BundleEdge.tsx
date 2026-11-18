// @supports LINEAGE_VIEW
import { BaseEdge, EdgeLabelRenderer, getBezierPath, type Edge, type EdgeProps } from '@xyflow/react';

import { Tip } from '@/components/ui/tooltip';

export type BundleEdgeData = { label: string; fields: string[] };
export type BundleFlowEdge = Edge<BundleEdgeData, 'bundle'>;

/** Fields copied unchanged from one class to the next, as one arrow; hover its label for their names. */
export function BundleEdge({ id, sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, style, markerEnd,
  data }: EdgeProps<BundleFlowEdge>) {
  const [path, labelX, labelY] = getBezierPath({ sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition });
  return (
    <>
      <BaseEdge id={id} path={path} style={style} markerEnd={markerEnd} />
      {data && (
        <EdgeLabelRenderer>
          <Tip content={data.fields.join(', ')}>
            <span tabIndex={0} style={{ transform: `translate(-50%, -50%) translate(${labelX}px, ${labelY}px)` }}
              className="nodrag nopan pointer-events-auto absolute rounded bg-card px-1 text-[11px] font-semibold
                text-muted-foreground outline-none focus-visible:ring-2 focus-visible:ring-ring">
              {data.label}
            </span>
          </Tip>
        </EdgeLabelRenderer>
      )}
    </>
  );
}
