// @supports PATHS_VIEW
import type { Node, NodeProps } from '@xyflow/react';
import { Server } from 'lucide-react';

import { Tip } from '@/components/ui/tooltip';

export type LaneNodeData = { service: string; width: number; height: number; tooltip: string; shade: boolean };
export type LaneFlowNode = Node<LaneNodeData, 'lane'>;

/** A band behind one service's steps. */
export function LaneNode({ data }: NodeProps<LaneFlowNode>) {
  return (
    <div style={{ width: data.width, height: data.height }}
      className={`rounded-xl border ${data.shade ? 'bg-muted/70' : 'bg-muted/35'}`}>
      <Tip content={data.tooltip} side="right">
        <div className="inline-flex items-center gap-1.5 px-3 pt-2 text-xs font-semibold tracking-wide text-muted-foreground uppercase">
          <Server className="size-3.5" />
          {data.service}
        </div>
      </Tip>
    </div>
  );
}
