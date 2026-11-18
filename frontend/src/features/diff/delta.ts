// @supports DIFF_VIEW
import type { Change } from '@/lib/types';

/** The top-level "and" terms of a requirement, outside parentheses. */
export function terms(requirement: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let start = 0;
  for (let i = 0; i < requirement.length; i++) {
    depth += requirement[i] === '(' ? 1 : requirement[i] === ')' ? -1 : 0;
    if (depth === 0 && requirement.startsWith(' and ', i)) {
      parts.push(requirement.slice(start, i));
      start = i + 5;
    }
  }
  parts.push(requirement.slice(start));
  return parts.map(part => part.trim()).filter(Boolean);
}

export interface Delta {
  text: string;
  removed: string[];
  added: string[];
  /** Before → after, when the two don't split into terms. */
  plain?: string;
}

/**
 * What a change did to the requirement, as terms removed and added ("− ROLE_ADMIN"), or before → after when the two
 * don't split into terms that way.
 */
export function deltaOf(change: Pick<Change, 'before' | 'after'>): Delta {
  const { before, after } = change;
  if (before == null || after == null) {
    const text = before == null ? `new: ${after ?? ''}` : `was: ${before}`;
    return { text, removed: [], added: [], plain: text };
  }
  const was = terms(before);
  const now = terms(after);
  const removed = was.filter(term => !now.includes(term));
  const added = now.filter(term => !was.includes(term));
  if (!removed.length && !added.length) {
    const text = `${before} → ${after}`;
    return { text, removed, added, plain: text };
  }
  return { text: [...removed.map(term => `− ${term}`), ...added.map(term => `+ ${term}`)].join(' '), removed, added };
}

export interface ChangeGroup {
  change: Change;
  delta: Delta;
  places: Change[];
}

/**
 * One group per distinct change: the same change on several endpoints or fields (say, one field check removed and
 * every route to that field weakened) is one row listing where it applies.
 */
export function changeGroups(changes: Change[]): ChangeGroup[] {
  const groups = new Map<string, ChangeGroup>();
  for (const change of changes) {
    const delta = deltaOf(change);
    // A new finding's message is its content, so each one keeps its own row.
    const key = [change.severity, change.kind, delta.text, change.kind === 'NEW_FINDING' ? change.message : ''].join('|');
    const group = groups.get(key) ?? { change, delta, places: [] };
    group.places.push(change);
    groups.set(key, group);
  }
  return [...groups.values()];
}
