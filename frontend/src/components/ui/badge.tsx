// @supports UI
import { cva, type VariantProps } from 'class-variance-authority';
import type { ComponentProps } from 'react';

import { cn } from '@/lib/utils';

const badgeVariants = cva(
  'inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-xs font-medium whitespace-nowrap'
    + ' [&_svg]:size-3 [&_svg]:shrink-0',
  {
    variants: {
      variant: {
        default: 'border-transparent bg-muted text-muted-foreground',
        outline: 'text-foreground',
        primary: 'border-transparent bg-primary/12 text-primary',
        request: 'border-transparent bg-request-soft text-request',
        method: 'border-transparent bg-method-soft text-method',
        field: 'border-transparent bg-field-soft text-field',
        egress: 'border-transparent bg-egress-soft text-egress',
        deny: 'border-transparent bg-deny-soft text-deny',
        mask: 'border-transparent bg-request-soft text-mask',
        grant: 'border-transparent bg-field-soft text-grant',
      },
    },
    defaultVariants: { variant: 'default' },
  },
);

export type BadgeVariant = NonNullable<VariantProps<typeof badgeVariants>['variant']>;

export function Badge({ className, variant, ...props }: ComponentProps<'span'> & VariantProps<typeof badgeVariants>) {
  return <span className={cn(badgeVariants({ variant }), className)} {...props} />;
}
