// @supports LEGEND_VIEW
import type { ReactNode } from 'react';

import { ViewHeader } from '@/components/common';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { CHANGE_KINDS, CREDENTIALS, DENIALS, FIELD_SOURCES, FINDING_KINDS, kindTitle, NO_CALLER, SCOPES, SEVERITIES }
  from '@/lib/format';

import { boxHeight, HEAD_H, rowHeight, type Box, type FieldItem, type Guard } from '../lineage/lineageLayout';
import { RecordCard } from '../lineage/RecordNode';
import { StepCard } from '../paths/StepNode';
import type { StepSpec } from '../paths/stepSpec';

const step = (spec: Partial<StepSpec> & Pick<StepSpec, 'kind' | 'head' | 'main'>): StepSpec =>
  ({ qid: spec.head, tooltip: '', ...spec });

const NODES: [StepSpec, string, string][] = [
  [step({ kind: 'ingress', method: 'GET', head: 'Ingress', main: '/profiles/{id}' }), 'Ingress',
    'Where a request or message enters a service: a controller mapping, a GraphQL operation (QUERY), a gRPC method'
      + ' (GRPC), a STOMP or RSocket message, a WebSocket handler, a SOAP operation, a message listener (KAFKA, RABBIT,'
      + ' JMS), a scheduled task (SCHEDULED), or an endpoint a library serves (Actuator, an authorization server, the H2'
      + ' console, API docs). Hover for the handler.'],
  [step({ kind: 'check', scope: 'HTTP_REQUEST', head: 'Rule /profiles/**', main: 'SCOPE_employees.read' }),
    'Request check', SCOPES.HTTP_REQUEST.title],
  [step({ kind: 'check', scope: 'METHOD', head: '@PreAuthorize', main: 'SCOPE_employees.read' }), 'Method check',
    SCOPES.METHOD.title],
  [step({ kind: 'check', scope: 'FIELD', head: 'ssn · @PreAuthorize', main: 'ROLE_ADMIN', denial: 'HANDLER' }),
    'Field check', SCOPES.FIELD.title + '. Guards one field, not the request.'],
  [step({ kind: 'egress', method: 'GET', head: 'RestClient', main: '/employees/{id}', credentials: 'token relay' }),
    'Egress', 'Where a request leaves the service (an HTTP client call site), and what it authenticates with. Hover for'
      + ' the client, base URL and the code that sets the credentials.'],
  [step({ kind: 'opaque', head: 'Opaque', main: 'Reflection (Method.invoke)' }), 'Opaque',
    'A call path the scan cannot follow, e.g. reflection. What runs after it is unknown.'],
  [step({ kind: 'check', scope: 'METHOD', head: '@PreAuthorize', main: 'ROLE_AUDITOR', observation: { subject: '',
    kind: 'LOCATION', count: 21, granted: 12, denied: 9 } }), 'Observed decisions',
  'How often Spring Security granted and denied this check in the traces the link read. "Not seen in traces": the'
      + ' traces had decisions, but none for this check. Spring Security records no decision span for'
      + ' @PreFilter/@PostFilter, nor Spring gRPC for its request rules, so traces cannot confirm those.'],
];

/** Everything the views draw, drawn with the same components the views use. */
export function LegendView() {
  return (
    <div>
      <ViewHeader title="Legend"
        description="What every shape, color, line and label in the other views means. The views link here instead of
          repeating it." />
      <div className="flex flex-col gap-5">
        <Section title="Request paths">
          {NODES.map(([spec, title, text]) => (
            <Item key={title} title={title} text={text}><div className="origin-left scale-90"><StepCard spec={spec} /></div></Item>
          ))}
          {Object.entries(DENIALS).filter(([kind]) => kind !== 'THROW').map(([kind, denial]) => (
            <Item key={kind} title={`"${denial.label}" when denied`} text={denial.title}>
              <span className="rounded bg-mask/15 px-1.5 py-0.5 text-xs font-semibold text-mask">{denial.label}</span>
            </Item>
          ))}
          <Item title="Denies when denied" text={DENIALS.THROW.title}>
            <span className="text-xs text-muted-foreground">no badge</span>
          </Item>
          <Item title="Local call path" text="An in-process call between two steps of one request path. Click it for the
            methods in between.">
            <LineSample color="var(--flow-direct)" />
          </Item>
          <Item title="On some branches only" text={'The step runs on some of the ways the code returns. It doesn\'t count'
            + ' for the endpoint on its own: a "Branches of" check asks for the weakest branch, or a BYPASSED finding says'
            + ' a way returns without it.'}>
            <LineSample color="var(--flow-direct)" dashed />
          </Item>
          <Item title="Network-observed link" text="A call between services that a trace confirmed. Arrows both ways: the
            request goes out, the response comes back. A message has one arrow: nothing comes back.">
            <LineSample color="var(--egress)" width={2} both />
          </Item>
          <Item title="Network-inferred link" text="Matched statically (URL template and port against a route, a GraphQL
            operation, a gRPC method, or a topic or queue) but not seen in a trace yet.">
            <LineSample color="var(--egress)" width={2} dashed both />
          </Item>
          {[...Object.values(CREDENTIALS), NO_CALLER].map(credentials => (
            <Item key={credentials.label} title={`"${credentials.label}"`} text={credentials.title}>
              <span className="rounded bg-egress/15 px-1.5 py-0.5 text-xs font-semibold text-egress">{credentials.label}</span>
            </Item>
          ))}
          <Item title="Service lane" text="One band per service. Hover its name for where its authorities come from and how
            fresh they are.">
            <div className="h-10 w-36 rounded-xl border bg-muted/70 px-3 pt-2 text-xs font-semibold text-muted-foreground uppercase">
              employee-service
            </div>
          </Item>
          <Item title="A check nobody calls" text={'On a path no caller starts (a message listener, a scheduled task, a'
            + ' WebSocket message) Spring Security finds no Authentication, so the check throws: it denies. "(@Async)" and'
            + ' "(other thread)" are the same on a thread the code hands work to, where it fails the work there but not'
            + ' the caller\'s request; "(..., waited for)" when the caller waits for that work (join(), block(), or'
            + ' returning it to Spring), so its request fails too.'}>
            <span className="text-xs text-muted-foreground">@PreAuthorize (no caller)</span>
          </Item>
          <Item title="Endpoints that end the same way" text="Endpoints whose paths end the same way (the same egress,
            called endpoint or field checks) share one card. The steps they share are drawn once and the arrows join
            there, so what differs stands out. Only steps followed by exactly the same steps are merged, so every path
            you can trace is a real one. A card that reads the same in several services is drawn once and names them.">
            <span className="text-xs text-muted-foreground">one card, several endpoints</span>
          </Item>
        </Section>

        <Section title="Field lineage">
          <Item title="Response class" text="A class in the endpoint's response, one row per field. A JSON path that differs
            from the field name is shown on the right. The top bar's color is the service.">
            <Record service="profile-service" title="ProfileView" role="response" shade={0}
              rows={[{ name: 'displayName' }, { name: 'email', note: 'json contact.email' }]} />
          </Item>
          <Item title="Source class, field check" text="Where values ultimately come from. A green line under a field is a
            field check that guards it on this path, with what the caller gets when it fails. Red chips are sensitivity
            labels from Provided facts.">
            <Record service="employee-service" title="Employee" role="source" shade={1}
              rows={[{ name: 'ssn', chips: ['PII'], guards: [{ text: 'ROLE_ADMIN', denial: 'HANDLER', tooltip: '' }] }]} />
          </Item>
          <Item title="Pass-through class" text="Every field is copied in and out unchanged, so its rows are hidden. Click
            its name to show them.">
            <Record service="employee-service" title="EmployeeResponse" role="" shade={1} collapsed
              rows={Array.from({ length: 7 }, (_, index) => ({ name: `field${index}` }))} />
          </Item>
          <Item title="Fields copied as is" text="Two or more fields copied unchanged (direct, same name) from one class to
            the next share one arrow. Hover it for the field names.">
            <LineSample color="var(--flow-direct)" width={3} label="7 fields as is" />
          </Item>
          {Object.entries(FIELD_SOURCES).map(([source, text]) => (
            <Item key={source} title={kindTitle(source)} text={text + (source === 'DIRECT' ? ' (the usual case, so its'
              + ' lines carry no label)' : '')}>
              <LineSample color={`var(--flow-${source.toLowerCase()})`} width={1.75}
                label={source === 'DIRECT' ? undefined : source.toLowerCase()} />
            </Item>
          ))}
          <Item title="Network flow" text="The value crosses a link between services, matched by JSON property name.
            Dashed: over a link no trace has confirmed yet.">
            <LineSample color="var(--flow-direct)" width={3.5} />
          </Item>
        </Section>

        <Section title="Tables">
          <Item title="Field asks nothing more" text="The field needs exactly what its endpoint row says.">
            <span className="text-sm text-muted-foreground">nothing more</span>
          </Item>
          <Item title="Shared by every field" text="What all of an endpoint's fields ask beyond the endpoint, e.g. a
            @PostFilter on the list they come from. Shown once; the fields show only what they add beyond it.">
            <span className="font-mono text-xs text-method">every field: + …</span>
          </Item>
          <Item title="Field asks more" text="What the field needs beyond its endpoint, e.g. a field check.">
            <span className="font-mono text-xs font-semibold text-method">+ ROLE_ADMIN</span>
          </Item>
          <Item title="No requirement" text={'Effective requirement "none": No Authorization, any caller gets it.'}>
            <Badge variant="deny">No Authorization</Badge>
          </Item>
          <Item title="Label" text="A sensitivity label inherited from the sources (Provided facts).">
            <Badge variant="outline">PII</Badge>
          </Item>
          <Item title="Policy violated" text="The field carries a label whose policy asks for more than the field requires.
            Hover for the policy.">
            <Badge variant="deny">PII policy ✗</Badge>
          </Item>
          <Item title="Over-scoped identity" text="Identities: the identity holds authorities that no check on its requests
            asked for. A test identity should hold only what its paths need.">
            <Badge variant="mask">ROLE_ADMIN</Badge>
          </Item>
          {Object.entries(SEVERITIES).map(([severity, text]) => (
            <Item key={severity} title={`Diff row: ${severity}`} text={text}>
              <Badge variant={severity === 'FAIL' ? 'deny' : severity === 'REVIEW' ? 'mask' : 'default'}>{severity}</Badge>
            </Item>
          ))}
        </Section>

        <Terms title="Finding kinds" texts={FINDING_KINDS} />
        <Terms title="Diff change kinds" texts={CHANGE_KINDS} />
      </div>
    </div>
  );
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <Card>
      <CardHeader><CardTitle>{title}</CardTitle></CardHeader>
      <CardContent className="grid gap-x-8 gap-y-5 md:grid-cols-2">{children}</CardContent>
    </Card>
  );
}

function Item({ title, text, children }: { title: string; text: string; children: ReactNode }) {
  return (
    <div className="flex items-start gap-4">
      <div className="flex w-48 shrink-0 justify-start">{children}</div>
      <div className="min-w-0">
        <div className="text-sm font-medium">{title}</div>
        <div className="text-sm text-muted-foreground">{text}</div>
      </div>
    </div>
  );
}

function Terms({ title, texts }: { title: string; texts: Record<string, string> }) {
  return (
    <Card>
      <CardHeader><CardTitle>{title}</CardTitle></CardHeader>
      <CardContent>
        <dl className="grid gap-x-6 gap-y-3 md:grid-cols-[14rem_1fr]">
          {Object.entries(texts).map(([kind, text]) => (
            <div key={kind} className="contents">
              <dt className="text-sm font-medium">{kindTitle(kind)}</dt>
              <dd className="text-sm text-muted-foreground">{text}</dd>
            </div>
          ))}
        </dl>
      </CardContent>
    </Card>
  );
}

function LineSample({ color, width = 1.5, dashed = false, both = false, label }: { color: string; width?: number;
  dashed?: boolean; both?: boolean; label?: string }) {
  const id = `legend-arrow-${color.replace(/\W/g, '')}`;
  return (
    <svg width="150" height="30" viewBox="0 0 150 30" aria-hidden="true">
      <defs>
        <marker id={id} viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
          <path d="M0,0 L10,5 L0,10 z" fill={color} />
        </marker>
      </defs>
      <path d="M8,20 L140,20" stroke={color} strokeWidth={width} strokeDasharray={dashed ? '6 4' : undefined}
        markerEnd={`url(#${id})`} markerStart={both ? `url(#${id})` : undefined} fill="none" />
      {label && <text x="74" y="11" textAnchor="middle" fontSize="11" fontWeight="600" fill={color}>{label}</text>}
    </svg>
  );
}

interface SampleRow {
  name: string;
  note?: string;
  chips?: string[];
  guards?: Guard[];
}

/** A lineage box drawn from a few sample rows. */
function Record({ service, title, role, shade, rows, collapsed = false }: { service: string; title: string;
  role: Box['role']; shade: number; rows: SampleRow[]; collapsed?: boolean }) {
  const box: Box = { key: title, service, className: title, fields: [], depth: 0, column: 0, x: 0, y: 0, height: 0, role,
    passThrough: collapsed, collapsed };
  let offset = HEAD_H;
  box.fields = rows.map(row => {
    const field: FieldItem = { qid: `${title}.${row.name}`, boxKey: title, name: row.name, in: [], out: [], box,
      guards: row.guards ?? [], note: row.note ?? '', chips: (row.chips ?? []).map(text => ({ text, tone: 'label' as const })),
      tooltip: '', wanted: 0, offset };
    offset += rowHeight(field);
    return field;
  });
  box.height = boxHeight(box);
  return <div className="origin-top-left scale-[0.72]" style={{ height: box.height * 0.72 }}>
    <RecordCard box={box} title={title} shade={shade} />
  </div>;
}
