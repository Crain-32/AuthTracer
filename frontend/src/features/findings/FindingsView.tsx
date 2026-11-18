// @supports FINDINGS_VIEW
import {
  AlertTriangle, Ban, CircleSlash, DoorOpen, EyeOff, FileWarning, Lock, Route, ShieldAlert, ShieldOff, Siren, Unplug,
} from 'lucide-react';
import type { ComponentType, ReactNode } from 'react';

import { EmptyState, ViewHeader } from '@/components/common';
import { Badge } from '@/components/ui/badge';
import { Card } from '@/components/ui/card';
import { Tip } from '@/components/ui/tooltip';
import { codeRef, FINDING_KINDS, kindTitle, shortNames } from '@/lib/format';
import type { Model, ServiceFinding } from '@/lib/model';

import { findingGroups, type FindingGroup } from './findingGroups';

/** The kinds that most often mean an endpoint is more open than it looks come first. */
const ORDER = ['OPEN_SENSITIVE_ENDPOINT', 'NOT_ENFORCED', 'BYPASSED', 'ALWAYS_GRANTED', 'UNRECOGNIZED_CHECK',
  'AUTHORITIES_IN_CODE', 'ALWAYS_DENIED', 'CHECK_AFTER_COMMIT', 'OPAQUE_CONFIG', 'OPAQUE_CALLPATH', 'RUNTIME_ONLY_CHECK',
  'UNMATCHED_CALL', 'PROVIDED_CONFLICT'];

const ICONS: Record<string, ComponentType<{ className?: string }>> = {
  OPEN_SENSITIVE_ENDPOINT: Siren,
  NOT_ENFORCED: ShieldOff,
  BYPASSED: Route,
  ALWAYS_GRANTED: DoorOpen,
  UNRECOGNIZED_CHECK: ShieldAlert,
  ALWAYS_DENIED: Ban,
  CHECK_AFTER_COMMIT: FileWarning,
  OPAQUE_CONFIG: EyeOff,
  OPAQUE_CALLPATH: CircleSlash,
  RUNTIME_ONLY_CHECK: Lock,
  UNMATCHED_CALL: Unplug,
};

const STRONG = new Set(['OPEN_SENSITIVE_ENDPOINT', 'NOT_ENFORCED', 'BYPASSED', 'ALWAYS_GRANTED', 'UNRECOGNIZED_CHECK']);

/** Findings by kind, then the Provided facts each scan applied. Only the kinds present are shown. */
export function FindingsView({ model }: { model: Model }) {
  const findings = model.findings();
  // Kinds this UI has no words for yet still show, after the ones it knows.
  const kinds = [...new Set([...ORDER, ...Object.keys(FINDING_KINDS), ...findings.map(finding => finding.kind)])]
    .filter(kind => findings.some(finding => finding.kind === kind));
  const provided = model.system.services.flatMap(graph => (graph.provided ?? []).map(fact => ({ service: graph.service, ...fact })));
  return (
    <div>
      <ViewHeader title="Findings"
        description="What the scan wants a person to look at: checks that aren't enforced or are skipped, configuration it
          can't read, and sensitive endpoints anyone can reach." />
      {!findings.length && <EmptyState icon={<AlertTriangle />} title="No findings">Nothing for a person to look at.</EmptyState>}
      <div className="flex flex-col gap-5">
        {kinds.map(kind => {
          const group = findings.filter(finding => finding.kind === kind);
          const Icon = ICONS[kind] ?? AlertTriangle;
          return (
            <Card key={kind} className="overflow-hidden">
              <div className="flex items-start gap-3 border-b px-5 py-4">
                <div className={`rounded-lg p-2 ${STRONG.has(kind) ? 'bg-deny-soft text-deny' : 'bg-request-soft text-request'}`}>
                  <Icon className="size-4" />
                </div>
                <div className="min-w-0 flex-1">
                  <h3 className="flex items-center gap-2 font-semibold">
                    {kindTitle(kind)} <Badge>{group.length}</Badge>
                  </h3>
                  <p className="mt-0.5 text-sm text-muted-foreground">{FINDING_KINDS[kind]}</p>
                </div>
              </div>
              <table className="w-full text-sm">
                <tbody>
                  {findingGroups(group).map((merged, index) => (
                    <tr key={index} className="border-b align-top last:border-b-0">
                      <td className="w-36 px-5 py-2.5 text-xs font-semibold tracking-wide text-muted-foreground uppercase">
                        {merged.findings[0].service}
                      </td>
                      {merged.findings.length === 1 ? (
                        <>
                          <td className="px-2 py-2.5">
                            <Tip content={merged.findings[0].message}><span>{shortNames(merged.findings[0].message)}</span></Tip>
                          </td>
                          <td className="px-5 py-2.5 text-right"><Location finding={merged.findings[0]} /></td>
                        </>
                      ) : (
                        <td colSpan={2} className="py-2.5 pr-5 pl-2"><MergedFindings group={merged} /></td>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
            </Card>
          );
        })}
        {provided.length > 0 && (
          <Card className="overflow-hidden">
            <div className="border-b px-5 py-4">
              <h3 className="flex items-center gap-2 font-semibold">Provided facts applied <Badge>{provided.length}</Badge></h3>
              <p className="mt-0.5 text-sm text-muted-foreground">
                Non-inferred facts from authtracer.yaml (LOCAL) and the Org file (ORG, ORG_OVERRIDE). When two cover the
                same thing, ORG_OVERRIDE beats ORG beats LOCAL.
              </p>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b bg-muted/50 text-left text-xs tracking-wide text-muted-foreground uppercase">
                    {['Service', 'Kind', 'Subject', 'Labels / requirement', 'Reason', 'Origin'].map(title => (
                      <th key={title} className="px-4 py-2 font-medium">{title}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {provided.map((fact, index) => (
                    <tr key={index} className="border-b last:border-b-0">
                      <td className="px-4 py-2">{fact.service}</td>
                      <td className="px-4 py-2">{fact.kind}</td>
                      <td className="px-4 py-2"><code>{fact.subject}</code></td>
                      <td className="px-4 py-2">{fact.requirement ?? (fact.labels ?? []).join(', ')}</td>
                      <td className="px-4 py-2 text-muted-foreground">{fact.reason ?? ''}</td>
                      <td className="px-4 py-2"><Badge variant="outline">{fact.origin}</Badge></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        )}
      </div>
    </div>
  );
}

function Location({ finding }: { finding: ServiceFinding }) {
  return (
    <Tip content={finding.location?.className}>
      <code className="text-xs text-muted-foreground">
        {finding.location?.method ? codeRef(finding.location) : finding.location?.className}
      </code>
    </Tip>
  );
}

/** The shared message once, its blanks marked, then what fills them for each finding and where it is. */
function MergedFindings({ group }: { group: FindingGroup }) {
  const parts: ReactNode[] = [];
  let text: string[] = [];
  const flush = () => text.length && parts.push(shortNames(text.join(' ')) + ' ');
  group.template.forEach((word, index) => {
    if (word === null) {
      flush();
      text = [];
      parts.push(<span key={index} className="mr-1 rounded border border-dashed border-primary/60 bg-primary/10 px-1.5
        text-xs text-primary">…</span>);
    }
    else {
      text.push(word);
    }
  });
  flush();
  return (
    <div>
      <p>{parts}</p>
      <ul className="mt-2 flex flex-col gap-1 border-l-2 border-primary/30 pl-3">
        {group.findings.map((finding, index) => (
          <li key={index} className="flex items-baseline justify-between gap-4">
            <Tip content={finding.message}>
              <code className="text-xs font-semibold text-primary">{group.values[index].map(shortNames).join(' · ')}</code>
            </Tip>
            <Location finding={finding} />
          </li>
        ))}
      </ul>
    </div>
  );
}
