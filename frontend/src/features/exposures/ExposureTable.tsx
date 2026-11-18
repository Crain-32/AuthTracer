// @supports EXPOSURES_VIEW, LINEAGE_VIEW, UI
import { ChevronRight } from 'lucide-react';
import { useMemo, type ReactNode } from 'react';

import { Endpoint, ServiceTag } from '@/components/common';
import { Badge } from '@/components/ui/badge';
import { Tip } from '@/components/ui/tooltip';
import { fieldIdText } from '@/lib/format';
import { useUi } from '@/lib/store';
import type { Exposure, Violation } from '@/lib/types';
import { cn } from '@/lib/utils';

import {
  alikeRuns, beyond, endpointGroups, MAX_ALIKE, runPrefix, sharedAddition, type EndpointGroup, type Row,
} from './exposureRows';

/**
 * Rows of exposures, grouped by endpoint: what a caller needs for the endpoint, then for each response field. A field
 * that asks no more than its endpoint says so quietly, so the fields with their own checks stand out. The checks on
 * the way are in the details panel (click a row).
 */
export function ExposureTable({ exposures }: { exposures: Exposure[] }) {
  const expanded = useUi(state => state.exposures.expanded);
  const setExposures = useUi(state => state.setExposures);
  const toggle = (key: string) => {
    const next = new Set(expanded);
    if (next.has(key)) {
      next.delete(key);
    }
    else {
      next.add(key);
    }
    setExposures({ expanded: next });
  };
  const labels = exposures.some(exposure => exposure.labels.length);
  const runs = useMemo(() => alikeRuns(endpointGroups(exposures)), [exposures]);
  return (
    <div className="overflow-x-auto rounded-xl border bg-card shadow-xs">
      <table className="w-full border-collapse text-sm">
        <thead>
          <tr className="border-b bg-muted/50 text-left text-xs font-medium tracking-wide text-muted-foreground uppercase">
            <th className="px-4 py-2.5 font-medium">Endpoint / field</th>
            <th className="px-4 py-2.5 font-medium">Requires</th>
            <th className="px-4 py-2.5 font-medium">Comes from</th>
            {labels && <th className="px-4 py-2.5 font-medium">Labels</th>}
          </tr>
        </thead>
        {runs.map(run => run.length > MAX_ALIKE
          ? <SummaryBody key={run[0][0].service + run[0][0].endpoint} run={run} labels={labels} expanded={expanded}
            toggle={toggle} />
          : run.map(group => <GroupBody key={group[0].service + group[0].endpoint} group={group} labels={labels}
            expanded={expanded} toggle={toggle} />))}
      </table>
    </div>
  );
}

interface BodyProps {
  labels: boolean;
  expanded: Set<string>;
  toggle: (key: string) => void;
}

/** "api-gateway 7 endpoints under /actuator · none"; click to list them. */
function SummaryBody({ run, labels, expanded, toggle }: BodyProps & { run: EndpointGroup[] }) {
  const first = run[0][0];
  const key = `${first.service} ${run.map(group => group[0].endpoint).join(',')}`;
  const open = expanded.has(key);
  const under = runPrefix(run);
  return (
    <>
      <tbody>
        <tr onClick={() => toggle(key)} className="cursor-pointer border-b hover:bg-muted/50">
          <td className="px-4 py-2.5">
            <Tip content={run.map(group => group[0].endpoint).join('\n')}>
              <button type="button" aria-expanded={open} className={ROW_BUTTON}>
                <ChevronRight className={cn('size-4 text-muted-foreground transition-transform', open && 'rotate-90')} />
                <ServiceTag>{first.service}</ServiceTag>
                <span className="font-medium">{run.length} endpoints{under && <> under <code>{under}</code></>}</span>
              </button>
            </Tip>
          </td>
          <td className="px-4 py-2.5"><Requires text={first.requirement} /></td>
          <td className="px-4 py-2.5 text-muted-foreground">no response fields</td>
          {labels && <td />}
        </tr>
      </tbody>
      {open && run.map(group => <GroupBody key={group[0].service + group[0].endpoint} group={group} labels={labels}
        expanded={expanded} toggle={toggle} />)}
    </>
  );
}

function GroupBody({ group, labels, expanded, toggle }: BodyProps & { group: EndpointGroup }) {
  const endpoint = group.find(exposure => !exposure.field);
  const fields = group.filter(exposure => exposure.field).sort((a, b) => a.field.localeCompare(b.field));
  const shared = endpoint ? sharedAddition(fields) : '';
  const key = `${endpoint?.service} ${endpoint?.endpoint} fields`;
  // Fields that ask nothing beyond their endpoint, carry no label and break no policy say so in one row.
  const plain = endpoint && !shared && fields.length > MAX_ALIKE && fields.every(field =>
    (field.adds === '' || field.requirement === endpoint.requirement) && !field.labels.length && !field.violations?.length);
  if (plain && !expanded.has(key)) {
    return (
      <tbody>
        <ExposureRow exposure={endpoint} endpoint={endpoint} shared={shared} labels={labels} />
        <tr onClick={() => toggle(key)} className="cursor-pointer border-b hover:bg-muted/50">
          <td className="py-2 pr-4 pl-10">
            <button type="button" aria-expanded={false} className={cn(ROW_BUTTON, 'min-w-0 text-muted-foreground')}>
              <ChevronRight className="size-4 shrink-0" />
              {fields.length} fields:
              <code className="truncate text-foreground/80">{fields.map(field => field.field).join(', ')}</code>
            </button>
          </td>
          <td className="px-4 py-2 text-muted-foreground">nothing more</td>
          <td />
          {labels && <td />}
        </tr>
      </tbody>
    );
  }
  return (
    <tbody>
      {[endpoint, ...fields].filter((row): row is Row => !!row).map(exposure => (
        <ExposureRow key={exposure.field} exposure={exposure} endpoint={endpoint} shared={shared} labels={labels} />
      ))}
    </tbody>
  );
}

/** A field shows only what it asks beyond its endpoint, when the server could work that out. */
function ExposureRow({ exposure, endpoint, shared, labels }: { exposure: Row; endpoint?: Row; shared: string;
  labels: boolean }) {
  // Rows are rebuilt from the exposures, so the selected one is recognized by what it is, not by identity.
  const selected = useUi(state => state.selection?.type === 'exposure' && sameRow(state.selection.exposure, exposure));
  const select = useUi(state => state.select);
  const adds = exposure.field && endpoint && exposure.adds !== null ? beyond(exposure.adds, shared) : null;
  const same = !!exposure.field && !!endpoint && (adds === '' || exposure.requirement === endpoint.requirement);
  let requires: ReactNode;
  if (same) {
    requires = <span className="text-muted-foreground">nothing more</span>;
  }
  else if (adds) {
    requires = <span className="font-mono text-xs font-semibold text-method">+ {adds}</span>;
  }
  else {
    requires = <Requires text={exposure.requirement} />;
  }
  return (
    <tr onClick={() => select({ type: 'exposure', exposure })}
      className={cn('cursor-pointer border-b align-top last:border-b-0 hover:bg-muted/60', !exposure.field && 'bg-muted/25',
        selected && 'bg-primary/10')}>
      <td className={cn('py-2.5 pr-4', exposure.field ? 'pl-10' : 'pl-4')}>
        {/* A button for the keyboard; its click reaches the row's handler. */}
        <button type="button" aria-pressed={selected} className={ROW_BUTTON}>
          {exposure.field ? <code className="text-[13px]">{exposure.field}</code> : (
            <span className="inline-flex min-w-0 flex-wrap items-center gap-2">
              <ServiceTag title={exposure.services?.join('\n')}>{exposure.service}</ServiceTag>
              <Endpoint text={exposure.endpoint} />
            </span>
          )}
        </button>
        {!exposure.field && (exposure.violations ?? []).map(violation => <PolicyBadge
          key={violation.label + violation.requires} violation={violation} text="policy ✗" className="ml-2" />)}
      </td>
      <td className="px-4 py-2.5">
        {requires}
        {!exposure.field && shared && (
          <div className="mt-1 font-mono text-xs text-method">every field: + {shared}</div>
        )}
      </td>
      <td className="px-4 py-2.5 text-xs text-muted-foreground">
        {exposure.sources.map(source => <div key={source}>{fieldIdText(source)}</div>)}
      </td>
      {labels && (
        <td className="px-4 py-2.5">
          <span className="flex flex-wrap gap-1">
            {exposure.labels.map(text => {
              const violation = (exposure.violations ?? []).find(found => found.label === text);
              return violation ? <PolicyBadge key={text} violation={violation} text={`${text} policy ✗`} />
                : <Badge key={text} variant="outline">{text}</Badge>;
            })}
          </span>
        </td>
      )}
    </tr>
  );
}

const ROW_BUTTON = 'inline-flex items-center gap-2 rounded-sm text-left outline-none focus-visible:ring-2'
  + ' focus-visible:ring-ring';

function sameRow(a: Row, b: Row): boolean {
  return a.service === b.service && a.ingress === b.ingress && a.field === b.field;
}

export function Requires({ text }: { text: string }) {
  return text === 'none' ? <Badge variant="deny">none</Badge>
    : <span className="font-mono text-xs font-semibold">{text}</span>;
}

function PolicyBadge({ violation, text, className }: { violation: Violation; text: string; className?: string }) {
  return (
    <Tip content={`The ${violation.label} policy requires ${violation.requires}${violation.reason ? ` (${violation.reason})` : ''}`}>
      <span tabIndex={0} className={cn('rounded-md outline-none focus-visible:ring-2 focus-visible:ring-ring', className)}>
        <Badge variant="deny">{text}</Badge>
      </span>
    </Tip>
  );
}
