import { render, type RenderResult } from '@testing-library/react';
import userEvent, { PointerEventsCheckLevel, type UserEvent } from '@testing-library/user-event';
import type { ReactElement } from 'react';

import { TooltipProvider } from '@/components/ui/tooltip';

/**
 * Renders as main.tsx does, inside the tooltips' provider (with no delay), with a user to drive it. jsdom applies no
 * stylesheet, so the class that gives a diagram's nodes their pointer events back can't win over React Flow's inline
 * style: the user doesn't check pointer events.
 */
export function renderUi(ui: ReactElement): RenderResult & { user: UserEvent } {
  const user = userEvent.setup({ pointerEventsCheck: PointerEventsCheckLevel.Never });
  return { user, ...render(<TooltipProvider delayDuration={0}>{ui}</TooltipProvider>) };
}
