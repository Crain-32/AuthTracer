// @supports FINDINGS_VIEW
import type { ServiceFinding } from '@/lib/model';

/** Messages that differ in more words than this stay apart: past it the shared text no longer reads as one finding. */
const MAX_VARYING = 2;

/**
 * Findings of one kind and service whose messages differ in a word or two, e.g. the same call made from three
 * handlers. They read as one message with a blank, and a line per finding saying what fills it.
 */
export interface FindingGroup {
  findings: ServiceFinding[];
  /** The message, word by word; null where the findings' words differ. */
  template: (string | null)[];
  /** Per finding, its words in the blanks, in order. */
  values: string[][];
}

export function findingGroups(findings: ServiceFinding[]): FindingGroup[] {
  const groups: { members: ServiceFinding[]; words: string[]; varying: Set<number> }[] = [];
  for (const finding of findings) {
    const words = finding.message.split(' ');
    let joined = false;
    for (const group of groups) {
      const first = group.members[0];
      if (first.service !== finding.service || first.kind !== finding.kind || group.words.length !== words.length) {
        continue;
      }
      const varying = new Set(group.varying);
      words.forEach((word, index) => word !== group.words[index] && varying.add(index));
      // Most of the message has to be shared, or a short one would merge with anything its length.
      if (varying.size <= MAX_VARYING && words.length - varying.size >= 3 * varying.size) {
        group.members.push(finding);
        group.varying = varying;
        joined = true;
        break;
      }
    }
    if (!joined) {
      groups.push({ members: [finding], words, varying: new Set() });
    }
  }
  return groups.map(({ members, words, varying }) => {
    const blanks = [...varying].sort((a, b) => a - b);
    return {
      findings: members,
      template: words.map((word, index) => varying.has(index) ? null : word),
      values: members.map(member => {
        const own = member.message.split(' ');
        return blanks.map(index => own[index]);
      }),
    };
  });
}
