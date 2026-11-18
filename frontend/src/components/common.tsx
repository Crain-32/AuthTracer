// @supports UI
import type { ReactNode } from 'react';

import { Badge } from '@/components/ui/badge';
import { Tip } from '@/components/ui/tooltip';
import { cn } from '@/lib/utils';

const METHOD_COLORS: Record<string, string> = {
  GET: 'bg-field-soft text-field',
  POST: 'bg-method-soft text-method',
  PUT: 'bg-request-soft text-request',
  PATCH: 'bg-request-soft text-request',
  DELETE: 'bg-deny-soft text-deny',
};

/** GET, POST, ... colored like an API reference; messaging and RPC kinds stay neutral. */
export function MethodBadge({ method, className }: { method: string; className?: string }) {
  return (
    <span className={cn('inline-flex h-5 min-w-12 items-center justify-center rounded px-1.5 font-mono text-[10.5px]'
      + ' font-semibold tracking-wide', METHOD_COLORS[method] ?? 'bg-muted text-muted-foreground', className)}>
      {method}
    </span>
  );
}

/** An endpoint as method and route, the route in monospace. */
export function Endpoint({ text, className }: { text: string; className?: string }) {
  const space = text.indexOf(' ');
  const method = space > 0 ? text.slice(0, space) : '';
  const route = space > 0 ? text.slice(space + 1) : text;
  return (
    <span className={cn('inline-flex min-w-0 items-center gap-2', className)}>
      {method && <MethodBadge method={method} />}
      <code className="truncate">{route}</code>
    </span>
  );
}

/** What a caller needs: "none" stands out as No Authorization. */
export function RequirementBadge({ requirement, className }: { requirement: string | undefined; className?: string }) {
  if (requirement === undefined) {
    return null;
  }
  if (requirement === 'none') {
    return <Badge variant="deny" className={className}>No Authorization</Badge>;
  }
  return (
    <Tip content={requirement}>
      <span className={cn('block min-w-0 truncate font-mono text-xs font-medium text-foreground', className)}>
        {requirement}
      </span>
    </Tip>
  );
}

export function ServiceTag({ children, title }: { children: ReactNode; title?: string }) {
  return (
    <Tip content={title}>
      <span className="truncate text-xs font-semibold tracking-wide text-muted-foreground uppercase">{children}</span>
    </Tip>
  );
}

/** A view's title, what it shows, and its controls. */
export function ViewHeader({ title, description, children }: { title: string; description: ReactNode;
  children?: ReactNode }) {
  return (
    <div className="mb-5 flex flex-wrap items-end justify-between gap-4">
      <div className="min-w-0">
        <h2 className="text-xl font-semibold tracking-tight">{title}</h2>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{description}</p>
      </div>
      {children && <div className="flex flex-wrap items-center gap-3">{children}</div>}
    </div>
  );
}

export function EmptyState({ icon, title, children }: { icon: ReactNode; title: string; children?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center rounded-xl border border-dashed px-6 py-16 text-center">
      <div className="mb-3 rounded-full bg-muted p-3 text-muted-foreground [&_svg]:size-6">{icon}</div>
      <h3 className="font-semibold">{title}</h3>
      {children && <div className="mt-1 max-w-md text-sm text-muted-foreground">{children}</div>}
    </div>
  );
}
