// @supports UI
import * as SwitchPrimitive from '@radix-ui/react-switch';
import type { ReactNode } from 'react';

/** A switch with its label. */
export function Switch({ checked, onChange, children }: { checked: boolean; onChange: (checked: boolean) => void;
  children: ReactNode }) {
  return (
    <label className="inline-flex cursor-pointer items-center gap-2 text-sm text-muted-foreground select-none">
      <SwitchPrimitive.Root checked={checked} onCheckedChange={onChange}
        className="relative inline-flex h-5 w-9 shrink-0 items-center rounded-full bg-border transition-colors outline-none
          focus-visible:ring-2 focus-visible:ring-ring/40 data-[state=checked]:bg-primary">
        <SwitchPrimitive.Thumb className="block size-4 translate-x-0.5 rounded-full bg-card shadow transition-transform
          data-[state=checked]:translate-x-[18px]" />
      </SwitchPrimitive.Root>
      {children}
    </label>
  );
}
