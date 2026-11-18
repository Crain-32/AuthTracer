// @supports DIFF_VIEW
import { CheckCircle2, CircleAlert, FileDiff, XCircle } from 'lucide-react';

import { EmptyState, ServiceTag, ViewHeader } from '@/components/common';
import { Badge, type BadgeVariant } from '@/components/ui/badge';
import { Card } from '@/components/ui/card';
import { Tip } from '@/components/ui/tooltip';
import { CHANGE_KINDS, kindTitle, shortNames } from '@/lib/format';
import { useUi } from '@/lib/store';
import type { Change, Severity } from '@/lib/types';
import { cn, groupBy } from '@/lib/utils';

import { changeGroups } from './delta';

const SEVERITY_BADGE: Record<Severity, BadgeVariant> = { FAIL: 'deny', REVIEW: 'mask', INFO: 'default' };

/** A diff report: whether the change passes, then one row per distinct authorization change. */
export function DiffView() {
  const diff = useUi(state => state.diff);
  const header = (
    <ViewHeader title="Diff report"
      description="How authorization changed between two revisions: weakened endpoints and fields fail the check,
        sideways changes and new findings need review." />
  );
  if (!diff) {
    return (
      <div>
        {header}
        <EmptyState icon={<FileDiff />} title="No diff report loaded">
          Write one with <code>./gradlew authtracer --args="diff … --json build/reports/authtracer/diff.json"</code> and
          open it with <b>Open file</b>.
        </EmptyState>
      </div>
    );
  }
  const { report, name } = diff;
  const count = (severity: Severity) => report.changes.filter(change => change.severity === severity).length;
  const result: Severity | 'PASS' = count('FAIL') ? 'FAIL' : count('REVIEW') ? 'REVIEW' : 'PASS';
  const Icon = result === 'FAIL' ? XCircle : result === 'REVIEW' ? CircleAlert : CheckCircle2;
  const groups = changeGroups(report.changes);
  const labels = report.changes.some(change => change.labels?.length);
  return (
    <div>
      {header}
      <Card className={cn('mb-5 flex flex-wrap items-center gap-4 px-5 py-4', result === 'FAIL' && 'border-deny/40 bg-deny-soft/40',
        result === 'REVIEW' && 'border-request/40 bg-request-soft/40', result === 'PASS' && 'border-field/40 bg-field-soft/40')}>
        <Icon className={cn('size-8', result === 'FAIL' ? 'text-deny' : result === 'REVIEW' ? 'text-request' : 'text-field')} />
        <div className="min-w-0 flex-1">
          <div className="text-lg font-semibold">{{ FAIL: 'Fails', REVIEW: 'Needs review', PASS: 'Passes' }[result]}</div>
          <div className="text-sm text-muted-foreground">
            {name}: <code>{report.base}</code> → <code>{report.head}</code>
          </div>
        </div>
        <div className="flex gap-2">
          <Badge variant="deny">{count('FAIL')} fail</Badge>
          <Badge variant="mask">{count('REVIEW')} review</Badge>
          <Badge>{count('INFO')} info</Badge>
        </div>
      </Card>
      {groups.length ? (
        <div className="overflow-x-auto rounded-xl border bg-card shadow-xs">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b bg-muted/50 text-left text-xs tracking-wide text-muted-foreground uppercase">
                {['Severity', 'Change', 'What changed', 'Where', labels ? 'Labels' : null, 'Why'].filter(Boolean).map(title => (
                  <th key={title} className="px-4 py-2.5 font-medium">{title}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {groups.map(({ change, delta, places }, index) => {
                const reasons = new Set(places.map(place => place.message ?? ''));
                return (
                  <tr key={index} className="border-b align-top last:border-b-0">
                    <td className="px-4 py-3"><Badge variant={SEVERITY_BADGE[change.severity]}>{change.severity}</Badge></td>
                    <td className="px-4 py-3">
                      <Tip content={CHANGE_KINDS[change.kind]}><span className="font-medium">{kindTitle(change.kind)}</span></Tip>
                    </td>
                    <td className="px-4 py-3 font-mono text-xs">
                      {delta.plain ?? (
                        <>
                          {delta.removed.map(term => <div key={term} className="text-deny">− {term}</div>)}
                          {delta.added.map(term => <div key={term} className="text-field">+ {term}</div>)}
                        </>
                      )}
                    </td>
                    <td className="px-4 py-3"><Places places={places} /></td>
                    {labels && (
                      <td className="px-4 py-3">
                        <span className="flex flex-wrap gap-1">
                          {[...new Set(places.flatMap(place => place.labels ?? []))].map(text => (
                            <Badge key={text} variant="outline">{text}</Badge>
                          ))}
                        </span>
                      </td>
                    )}
                    <td className="max-w-md px-4 py-3 text-muted-foreground">
                      <Tip content={[...reasons].join('\n')}>
                        <span>{reasons.size === 1 ? shortNames(change.message) : CHANGE_KINDS[change.kind]}</span>
                      </Tip>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : (
        <EmptyState icon={<CheckCircle2 />} title="No authorization changes" />
      )}
    </div>
  );
}

/** One line per endpoint, its changed fields after it; hover a field (or the endpoint) for its own details. */
function Places({ places }: { places: Change[] }) {
  const endpoints = groupBy(places, place => `${place.service} ${place.endpoint}`);
  const detail = (place: Change) => `${shortNames(place.message)}\n${place.before ?? '(none)'}\n→ ${place.after ?? '(none)'}`;
  return (
    <div className="flex flex-col gap-1">
      {[...endpoints.values()].map(list => {
        const fields = list.filter(place => place.field);
        return (
          <Tip key={list[0].service + list[0].endpoint} content={fields.length ? undefined : detail(list[0])}>
            <div className="flex flex-wrap items-center gap-x-2">
              <ServiceTag>{list[0].service}</ServiceTag>
              <code className="text-xs">{shortNames(list[0].endpoint)}</code>
              {fields.length > 0 && <span className="text-muted-foreground">·</span>}
              {fields.map(place => (
                <Tip key={place.field} content={detail(place)}><code className="text-xs text-method">{place.field}</code></Tip>
              ))}
            </div>
          </Tip>
        );
      })}
    </div>
  );
}
