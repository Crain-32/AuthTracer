// @supports PATHS_VIEW, LEGEND_VIEW
import { Handle, Position, type Node, type NodeProps } from '@xyflow/react';
import { ArrowRightToLine, CircleHelp, Send, ShieldCheck } from 'lucide-react';
import type { ReactNode } from 'react';

import { MethodBadge } from '@/components/common';
import { Tip } from '@/components/ui/tooltip';
import { DENIALS } from '@/lib/format';
import { useUi } from '@/lib/store';
import { cn } from '@/lib/utils';

import { STEP_H, STEP_W } from './pathLayout';
import type { StepSpec } from './stepSpec';

export type StepNodeData = { spec: StepSpec; selected: boolean };
export type StepFlowNode = Node<StepNodeData, 'step'>;

const SCOPE_STYLES: Record<string, string> = {
  HTTP_REQUEST: 'border-request/45 bg-request-soft/60 [--accent-bar:var(--request)]',
  METHOD: 'border-method/45 bg-method-soft/60 [--accent-bar:var(--method)]',
  FIELD: 'border-field/45 bg-field-soft/60 [--accent-bar:var(--field)]',
};

const KIND_STYLES: Record<string, string> = {
  ingress: 'border-ingress/35 bg-card [--accent-bar:var(--ingress)] rounded-2xl',
  egress: 'border-egress/45 bg-egress-soft/60 [--accent-bar:var(--egress)]',
  opaque: 'border-dashed border-muted-foreground/50 bg-muted [--accent-bar:var(--muted-foreground)]',
};

const SCOPE_LABEL: Record<string, string> = { HTTP_REQUEST: 'Request', METHOD: 'Method', FIELD: 'Field' };

/** One step of a request path on a diagram, with the handles its arrows attach to. A button: it shows its details. */
export function StepNode({ data }: NodeProps<StepFlowNode>) {
  const select = useUi(state => state.select);
  return (
    <StepCard spec={data.spec} selected={data.selected} onActivate={() => select({ type: 'node', qid: data.spec.qid })}>
      <Handle type="target" position={Position.Left} className="!size-1.5 !min-h-0 !min-w-0 !border-0 !bg-transparent" />
      <Handle type="source" position={Position.Right} className="!size-1.5 !min-h-0 !min-w-0 !border-0 !bg-transparent" />
    </StepCard>
  );
}

/** One step of a request path: an ingress, a check, an egress or an opaque call. The legend draws it too. */
export function StepCard({ spec, selected = false, onActivate, children }: { spec: StepSpec; selected?: boolean;
  onActivate?: () => void; children?: ReactNode }) {
  const style = spec.kind === 'check' ? SCOPE_STYLES[spec.scope ?? 'METHOD'] : KIND_STYLES[spec.kind];
  const Element = onActivate ? 'button' : 'div';
  return (
    <Tip content={spec.tooltip} side="bottom">
      <Element style={{ width: STEP_W, height: STEP_H }} onClick={onActivate}
        {...(onActivate && { type: 'button', 'aria-pressed': selected })}
        className={cn('group relative flex flex-col justify-center gap-1 overflow-hidden rounded-lg border py-2 pr-2.5'
          + ' pl-3.5 text-left shadow-xs transition-shadow outline-none focus-visible:ring-2 focus-visible:ring-ring',
        // React Flow turns pointer events off on nodes it handles no clicks for: this card handles its own.
        onActivate && 'pointer-events-auto cursor-pointer hover:shadow-md', style,
        selected && 'ring-2 ring-primary ring-offset-2 ring-offset-background')}>
        <span className="absolute inset-y-0 left-0 w-1 bg-[var(--accent-bar)]" />
        {children}
        <div className="flex min-w-0 items-center gap-1.5 text-[11px] font-medium text-muted-foreground">
          <KindIcon spec={spec} />
          <span className="truncate">{spec.kind === 'check' ? `${SCOPE_LABEL[spec.scope ?? 'METHOD']} · ${spec.head}` : spec.head}</span>
          <span className="ml-auto flex shrink-0 gap-1">
            {spec.denial && <span className="rounded bg-mask/15 px-1 text-[10px] font-semibold text-mask">{DENIALS[spec.denial]?.label}</span>}
            {spec.credentials && <span className="rounded bg-egress/15 px-1 text-[10px] font-semibold text-egress">{spec.credentials}</span>}
          </span>
        </div>
        <div className="flex min-w-0 items-center gap-1.5">
          {spec.method && <MethodBadge method={spec.method} className="h-4 min-w-0 px-1 text-[9.5px]" />}
          <span className={cn('truncate text-[13px] font-semibold', spec.kind !== 'check' && 'font-mono text-[12px]')}>
            {spec.main}
          </span>
        </div>
        <Observed observation={spec.observation} untraced={spec.untraced} />
      </Element>
    </Tip>
  );
}

function KindIcon({ spec }: { spec: StepSpec }) {
  const className = 'size-3.5 shrink-0';
  switch (spec.kind) {
    case 'ingress':
      return <ArrowRightToLine className={className} />;
    case 'egress':
      return <Send className={className} />;
    case 'check':
      return <ShieldCheck className={className} />;
    default:
      return <CircleHelp className={className} />;
  }
}

function Observed({ observation, untraced }: { observation: StepSpec['observation']; untraced?: string }) {
  if (!observation) {
    return null;
  }
  if (observation === 'unseen' || observation === 'untraced') {
    return (
      <div className="text-[10.5px] text-muted-foreground italic">
        {observation === 'unseen' ? 'not seen in traces' : untraced}
      </div>
    );
  }
  return (
    <div className="text-[10.5px] font-medium">
      <span className="text-grant">{observation.granted} granted</span>
      <span className="text-muted-foreground"> · </span>
      <span className="text-deny">{observation.denied} denied</span>
    </div>
  );
}
