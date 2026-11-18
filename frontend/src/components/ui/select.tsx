// @supports UI
import * as SelectPrimitive from '@radix-ui/react-select';
import { Check, ChevronDown } from 'lucide-react';

import { cn } from '@/lib/utils';

export interface Option {
  value: string;
  label: string;
}

/**
 * A select of plain options. Radix's select can't hold an empty value, so '' maps to a sentinel.
 */
export function Select({ value, onChange, options, placeholder, className, label }: { value: string;
  onChange: (value: string) => void; options: Option[]; placeholder?: string; className?: string; label?: string }) {
  const EMPTY = '\u0000';
  return (
    <SelectPrimitive.Root value={value === '' ? (placeholder ? '' : EMPTY) : value}
      onValueChange={next => onChange(next === EMPTY ? '' : next)}>
      <SelectPrimitive.Trigger
        aria-label={label}
        className={cn('inline-flex h-9 min-w-0 items-center justify-between gap-2 rounded-lg border bg-card px-3 text-sm'
          + ' shadow-xs outline-none focus-visible:ring-2 focus-visible:ring-ring/30 data-[placeholder]:text-muted-foreground'
          + ' cursor-pointer', className)}
      >
        <span className="truncate"><SelectPrimitive.Value placeholder={placeholder} /></span>
        <SelectPrimitive.Icon><ChevronDown className="size-4 opacity-60" /></SelectPrimitive.Icon>
      </SelectPrimitive.Trigger>
      <SelectPrimitive.Portal>
        <SelectPrimitive.Content position="popper" sideOffset={4}
          className="z-50 max-h-[min(24rem,var(--radix-select-content-available-height))] min-w-[var(--radix-select-trigger-width)]
            overflow-hidden rounded-lg border bg-card text-sm shadow-lg">
          <SelectPrimitive.Viewport className="p-1">
            {options.map(option => (
              <SelectPrimitive.Item key={option.value} value={option.value === '' ? EMPTY : option.value}
                className="relative flex cursor-pointer items-center rounded-md py-1.5 pr-8 pl-2 outline-none select-none
                  data-[highlighted]:bg-muted">
                <SelectPrimitive.ItemText>{option.label}</SelectPrimitive.ItemText>
                <SelectPrimitive.ItemIndicator className="absolute right-2">
                  <Check className="size-4" />
                </SelectPrimitive.ItemIndicator>
              </SelectPrimitive.Item>
            ))}
          </SelectPrimitive.Viewport>
        </SelectPrimitive.Content>
      </SelectPrimitive.Portal>
    </SelectPrimitive.Root>
  );
}
