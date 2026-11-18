// @supports PATHS_VIEW, LINEAGE_VIEW
import { ReactFlow, type Edge, type Node, type ReactFlowProps } from '@xyflow/react';
import { useMemo } from 'react';

import { useElementWidth } from '@/hooks/useElementWidth';
import { useInView } from '@/hooks/useInView';

/** Wider diagrams than this zoom allows scroll sideways instead of shrinking further. */
const MIN_ZOOM = 0.8;

type FlowProps<N extends Node, E extends Edge> = Pick<ReactFlowProps<N, E>, 'nodes' | 'edges' | 'nodeTypes'
  | 'edgeTypes' | 'onEdgeClick'>;

/**
 * A read-only diagram at a fixed scale: shrunk to fit its container down to MIN_ZOOM, scrolling sideways past that.
 * The scale follows the container (the details panel opening narrows it), and the diagram is only drawn once it comes
 * near the viewport, so a page of open cards stays quick.
 */
export function ScaledFlow<N extends Node, E extends Edge>({ width, height, minHeight, ...flow }: FlowProps<N, E> & {
  width: number; height: number; minHeight: number }) {
  const [ref, available] = useElementWidth<HTMLDivElement>();
  const near = useInView(ref);
  const zoom = available ? Math.max(MIN_ZOOM, Math.min(1, available / width)) : 1;
  const viewport = useMemo(() => ({ x: 0, y: 0, zoom }), [zoom]);
  return (
    <div ref={ref} className="w-full overflow-x-auto">
      {available > 0 && (
        <div style={{ width: width * zoom, height: Math.max(minHeight, height * zoom) }}>
          {near && (
            <ReactFlow<N, E> {...flow} viewport={viewport} panOnDrag={false} zoomOnScroll={false} zoomOnPinch={false}
              zoomOnDoubleClick={false} preventScrolling={false} nodesConnectable={false} nodesDraggable={false}
              elementsSelectable={false} nodesFocusable={false} edgesFocusable={false} />
          )}
        </div>
      )}
    </div>
  );
}
