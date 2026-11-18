// @supports UI
import * as TooltipPrimitive from '@radix-ui/react-tooltip';
import type { ReactNode } from 'react';

import { cn } from '@/lib/utils';

export const TooltipProvider = TooltipPrimitive.Provider;

/** A tooltip on its child; plain text keeps its line breaks. */
export function Tip({ content, children, side = 'top', className }: { content: ReactNode; children: ReactNode;
  side?: 'top' | 'right' | 'bottom' | 'left'; className?: string }) {
  if (content === null || content === undefined || content === '') {
    return <>{children}</>;
  }
  return (
    <TooltipPrimitive.Root>
      <TooltipPrimitive.Trigger asChild>{children}</TooltipPrimitive.Trigger>
      <TooltipPrimitive.Portal>
        <TooltipPrimitive.Content
          side={side}
          sideOffset={6}
          collisionPadding={8}
          className={cn('z-50 max-w-md rounded-lg bg-foreground px-3 py-2 text-xs leading-relaxed whitespace-pre-line'
            + ' text-background shadow-lg', className)}
        >
          {content}
          <TooltipPrimitive.Arrow className="fill-foreground" />
        </TooltipPrimitive.Content>
      </TooltipPrimitive.Portal>
    </TooltipPrimitive.Root>
  );
}
