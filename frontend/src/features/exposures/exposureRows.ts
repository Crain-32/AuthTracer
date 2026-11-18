// @supports EXPOSURES_VIEW
import type { Exposure } from '@/lib/types';
import { commonPrefix, firstSegment, groupBy, runsBy } from '@/lib/utils';

/** More endpoints than this with no response fields and the same requirement, in a row, are one summary row. */
export const MAX_ALIKE = 3;

/** An exposure as a row shows it: the same endpoint in several services is one row naming them. */
export interface Row extends Exposure {
  services?: string[];
}

/** One endpoint and its response fields. */
export type EndpointGroup = Row[];

/**
 * Rows grouped by endpoint. The same endpoint with no fields, needing the same in several services (each one's
 * actuator health, say), is one row naming the services.
 */
export function endpointGroups(exposures: Exposure[]): EndpointGroup[] {
  const groups: Map<string, Row[]> = groupBy(exposures, exposure => `${exposure.service} ${exposure.endpoint}`);
  const twins = new Map<string, { group: Row[]; services: string[] }>();
  for (const [key, group] of [...groups]) {
    if (group.length !== 1 || group[0].field || group[0].violations?.length) {
      continue;
    }
    const shape = `${group[0].endpoint}|${group[0].requirement}`;
    const twin = twins.get(shape);
    if (twin) {
      twin.services.push(group[0].service);
      groups.delete(key);
    }
    else {
      twins.set(shape, { group, services: [group[0].service] });
    }
  }
  for (const { group, services } of twins.values()) {
    if (services.length > 1) {
      group[0] = { ...group[0], services,
        service: services.length > 3 ? `${services.length} services` : services.join(', ') };
    }
  }
  return [...groups.values()];
}

/** Consecutive endpoints with no response fields that read the same: service, requirement, first path segment. */
export function alikeRuns(groups: EndpointGroup[]): EndpointGroup[][] {
  const key = (group: EndpointGroup) => {
    if (group.length !== 1 || group[0].field || group[0].violations?.length) {
      return null;
    }
    return [group[0].service, group[0].requirement, firstSegment(group[0].endpoint.split(' ')[1] ?? '')].join('|');
  };
  return runsBy(groups, key);
}

/** The common route prefix of a run of endpoints, e.g. /actuator. */
export function runPrefix(run: EndpointGroup[]): string {
  return commonPrefix(run.map(group => group[0].endpoint.split(' ')[1] ?? ''));
}

/**
 * What every field of an endpoint adds first, e.g. a @PostFilter on the list they come from. It is shown once, on the
 * endpoint row, and the fields show only what they add beyond it.
 */
export function sharedAddition(fields: Exposure[]): string {
  if (fields.length < 2 || fields.some(field => !field.adds)) {
    return '';
  }
  const terms = fields.map(field => field.adds!.split(' and '));
  let shared = 0;
  while (terms.every(list => shared < list.length && list[shared] === terms[0][shared])) {
    shared++;
  }
  return terms[0].slice(0, shared).join(' and ');
}

/** What a field adds beyond what every field of its endpoint adds. */
export function beyond(adds: string, shared: string): string {
  return !shared ? adds : adds === shared ? '' : adds.slice(shared.length + ' and '.length);
}

/** Whether every word appears in what the exposure says: where it is, what it needs, its sources and checks. */
export function matchesFilter(exposure: Exposure, words: string[]): boolean {
  const text = [exposure.service, exposure.endpoint, exposure.field, exposure.requirement, ...exposure.sources,
    ...exposure.labels, ...(exposure.violations ?? []).map(violation => `policy violation ${violation.label}`),
    ...exposure.steps.flatMap(step => [step.mechanism, step.requirement, step.location])].join(' ').toLowerCase();
  return words.every(word => text.includes(word));
}
