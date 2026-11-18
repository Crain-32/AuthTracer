// @supports LINEAGE_VIEW, LEGEND_VIEW
import { Handle, Position, type Node, type NodeProps } from '@xyflow/react';
import { Database, FileOutput, Layers, ShieldCheck } from 'lucide-react';

import { Tip } from '@/components/ui/tooltip';
import { DENIALS } from '@/lib/format';
import { cn } from '@/lib/utils';

import { BOX_W, GUARD_H, HEAD_H, ROW_H, type Box } from './lineageLayout';

export interface ExtraHandle {
  id: string;
  type: 'source' | 'target';
  top: number;
}

export type RecordNodeData = {
  box: Box;
  title: string;
  shade: number;
  extraHandles: ExtraHandle[];
  selectedQid: string | null;
  onToggle?: () => void;
  onSelectField: (qid: string) => void;
};
export type RecordFlowNode = Node<RecordNodeData, 'record'>;

const SHADES = ['bg-method', 'bg-egress', 'bg-field', 'bg-request'];

const hidden = '!size-1.5 !min-h-0 !min-w-0 !border-0 !bg-transparent';

/** A class on a lineage diagram, with the handles its arrows attach to. */
export function RecordNode({ data }: NodeProps<RecordFlowNode>) {
  return <RecordCard {...data} handles />;
}

/** A class as one box with a row per field; a pass-through class collapses to one line. The legend draws it too. */
export function RecordCard({ box, title, shade, extraHandles = [], selectedQid = null, onToggle, onSelectField,
  handles = false }: Omit<RecordNodeData, 'extraHandles' | 'selectedQid' | 'onSelectField'> & {
  extraHandles?: ExtraHandle[]; selectedQid?: string | null; onSelectField?: (qid: string) => void; handles?: boolean }) {
  const count = `${box.fields.length} ${box.fields.length === 1 ? 'field' : 'fields'}`;
  const RoleIcon = box.role === 'response' ? FileOutput : box.role === 'source' ? Database : Layers;
  const HeadElement = onToggle ? 'button' : 'div';
  const RowElement = onSelectField ? 'button' : 'div';
  return (
    <div style={{ width: BOX_W, height: box.height }}
      // React Flow turns pointer events off on nodes it handles no clicks for: the rows handle their own.
      className={cn('pointer-events-auto relative overflow-hidden rounded-xl border bg-card shadow-sm',
        box.role === 'response' && 'ring-1 ring-primary/40')}>
      <span className={cn('absolute inset-x-0 top-0 h-1', SHADES[shade % SHADES.length])} />
      <Tip content={`${box.className}${box.passThrough ? `\n${count}, copied in and out unchanged: click to `
        + `${box.collapsed ? 'show' : 'hide'} them` : ''}`}>
        <HeadElement style={{ height: HEAD_H }} onClick={onToggle}
          {...(onToggle && { type: 'button', 'aria-expanded': !box.collapsed })}
          className={cn('flex w-full flex-col justify-center border-b px-3 pt-1 text-left outline-none',
            onToggle && 'cursor-pointer hover:bg-muted/60 focus-visible:bg-muted')}>
          <span className="flex items-center gap-1.5 text-[10.5px] font-semibold tracking-wide text-muted-foreground uppercase">
            <RoleIcon className="size-3" />
            {box.service}{box.role && ` · ${box.role}`}
          </span>
          <span className="truncate text-[13px] font-semibold">{title}</span>
        </HeadElement>
      </Tip>
      {box.collapsed ? (
        <div style={{ height: ROW_H }} className="flex items-center px-3 text-xs text-muted-foreground italic">
          {count}, unchanged
        </div>
      ) : box.fields.map(field => (
        <div key={field.qid} onClick={() => onSelectField?.(field.qid)}
          className={cn('cursor-pointer shadow-[inset_0_-1px_0_var(--border)] last:shadow-none hover:bg-muted/60',
            selectedQid === field.qid && 'bg-primary/10')}>
          <Tip content={field.tooltip} side="right">
            {/* A button for the keyboard; its click reaches the row's handler. */}
            <RowElement style={{ height: ROW_H }} {...(onSelectField && { type: 'button' })}
              className="flex w-full items-center gap-2 px-3 text-left text-[12.5px] outline-none focus-visible:bg-muted">
              <code className="truncate font-medium">{field.name}</code>
              {field.chips.map(chip => (
                <span key={chip.text} className={cn('rounded px-1 text-[10px] font-semibold',
                  chip.tone === 'label' ? 'bg-deny-soft text-deny' : 'bg-muted text-muted-foreground')}>{chip.text}</span>
              ))}
              {!field.chips.length && field.note && (
                <span className="ml-auto truncate text-[11px] text-muted-foreground">{field.note}</span>
              )}
            </RowElement>
          </Tip>
          {field.guards.map(guard => (
            <Tip key={guard.text + guard.denial} content={guard.tooltip} side="right">
              <div style={{ height: GUARD_H }} className="px-2 pb-1">
                <div className="flex h-full items-center gap-1.5 rounded-md bg-field-soft px-2 text-[11px] text-field">
                  <ShieldCheck className="size-3 shrink-0" />
                  <span className="truncate">check {guard.text}</span>
                  {guard.denial && guard.denial !== 'THROW' && (
                    <span className="ml-auto rounded bg-mask/15 px-1 text-[10px] font-semibold text-mask">
                      {DENIALS[guard.denial]?.label}
                    </span>
                  )}
                </div>
              </div>
            </Tip>
          ))}
          {handles && <Handle id={`in:${field.qid}`} type="target" position={Position.Left}
            style={{ top: field.offset + ROW_H / 2 }} className={hidden} />}
          {handles && <Handle id={`out:${field.qid}`} type="source" position={Position.Right}
            style={{ top: field.offset + ROW_H / 2 }} className={hidden} />}
        </div>
      ))}
      {handles && extraHandles.map(handle => (
        <Handle key={handle.id} id={handle.id} type={handle.type}
          position={handle.type === 'source' ? Position.Right : Position.Left} style={{ top: handle.top }}
          className={hidden} />
      ))}
    </div>
  );
}
