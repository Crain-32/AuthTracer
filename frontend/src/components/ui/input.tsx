// @supports UI
import type { ComponentProps } from 'react';

import { cn } from '@/lib/utils';

export function Input({ className, ...props }: ComponentProps<'input'>) {
  return (
    <input
      className={cn('h-9 w-full min-w-0 rounded-lg border bg-card px-3 text-sm shadow-xs outline-none transition-colors'
        + ' placeholder:text-muted-foreground focus-visible:border-ring focus-visible:ring-2 focus-visible:ring-ring/30',
      className)}
      {...props}
    />
  );
}
