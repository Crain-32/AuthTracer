// @supports UI
import { ChevronRight, GitBranch, X } from 'lucide-react';
import type { ReactNode } from 'react';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Tip } from '@/components/ui/tooltip';
import {
  authorityText, BROKERS, codeRef, count, CREDENTIALS, DENIALS, endpointText, fieldIdText, FIELD_SOURCES, fullCodeRef,
  NO_CALLER, payload, requirementText, SCOPES, untraced,
} from '@/lib/format';
import { nodeOf, qualify, serviceOf, type Model } from '@/lib/model';
import { useUi, type Selection } from '@/lib/store';
import type { CodeRef, Edge, Exposure, Flow } from '@/lib/types';

import { Requires } from '../exposures/ExposureTable';

/** The side panel: everything known about the clicked node, line or row. */
export function DetailsPanel({ model, selection }: { model: Model; selection: Selection }) {
  const select = useUi(state => state.select);
  let content: Content;
  switch (selection.type) {
    case 'node':
      content = nodeDetails(model, selection.qid);
      break;
    case 'edge':
      content = edgeDetails(selection.service, selection.edge);
      break;
    case 'link':
      content = linkDetails(model, selection.link);
      break;
    case 'flow':
      content = flowDetails(selection.flow);
      break;
    default:
      content = { kind: 'Exposure', title: selection.exposure.field || 'Endpoint', rows: [], body: <ExposureDetails exposure={selection.exposure} /> };
  }
  return (
    <aside className="flex h-full flex-col">
      <div className="flex items-start gap-3 border-b px-5 py-4">
        <div className="min-w-0 flex-1">
          <div className="text-xs font-semibold tracking-wide text-muted-foreground uppercase">{content.kind}</div>
          <h3 className="mt-0.5 font-mono text-sm font-semibold break-all">{content.title}</h3>
        </div>
        <Button variant="ghost" size="icon-sm" aria-label="Close details" onClick={() => select(null)}><X /></Button>
      </div>
      <div className="flex-1 overflow-y-auto px-5 py-4">
        {content.body}
        {content.rows.length > 0 && <Props rows={content.rows} />}
        {content.raw !== undefined && (
          <details className="group mt-5">
            <summary className="flex cursor-pointer list-none items-center gap-1 text-xs font-medium text-muted-foreground">
              <ChevronRight className="size-3.5 transition-transform group-open:rotate-90" /> JSON
            </summary>
            <pre className="mt-2 max-h-80 overflow-auto rounded-lg bg-muted p-3 text-[11px] leading-relaxed">
              {JSON.stringify(content.raw, null, 2)}
            </pre>
          </details>
        )}
      </div>
    </aside>
  );
}

interface Content {
  kind: string;
  title: string;
  rows: [string, ReactNode][];
  body?: ReactNode;
  raw?: unknown;
}

function Props({ rows }: { rows: [string, ReactNode][] }) {
  const present = rows.filter(([, value]) => value !== undefined && value !== null && value !== ''
    && !(Array.isArray(value) && !value.length));
  return (
    <dl className="grid grid-cols-[7.5rem_1fr] gap-x-3 gap-y-2.5 text-sm">
      {present.map(([name, value]) => (
        <div key={name} className="contents">
          <dt className="text-muted-foreground">{name}</dt>
          <dd className="min-w-0 break-words">{value}</dd>
        </div>
      ))}
    </dl>
  );
}

function Code({ children }: { children: ReactNode }) {
  return <code className="rounded bg-muted px-1 py-0.5 text-[12px] break-all">{children}</code>;
}

/** Where in the code, short; the full signature on hover. */
function CodeRefText({ target }: { target: CodeRef | undefined }) {
  return <Tip content={fullCodeRef(target)}><span><Code>{codeRef(target)}</Code></span></Tip>;
}

function NodeLink({ qid, children }: { qid: string; children: ReactNode }) {
  const select = useUi(state => state.select);
  return (
    <button className="cursor-pointer text-left text-primary hover:underline" onClick={() => select({ type: 'node', qid })}>
      {children}
    </button>
  );
}

function ExposureDetails({ exposure }: { exposure: Exposure }) {
  const showLineage = useUi(state => state.showLineage);
  return (
    <div className="flex flex-col gap-4">
      <div className="text-sm text-muted-foreground">{exposure.service} · <code>{exposure.endpoint}</code></div>
      <Props rows={[
        ['Requires', <Requires key="requires" text={exposure.requirement} />],
        ['Checks, in order', exposure.steps.length ? (
          <ol key="steps" className="flex flex-col gap-1.5">
            {exposure.steps.map(step => (
              <li key={step.location} className="flex flex-col">
                <NodeLink qid={step.location}>
                  {serviceOf(step.location) !== exposure.service ? `${serviceOf(step.location)} · ` : ''}{step.mechanism}
                </NodeLink>
                <span className="font-mono text-xs">{step.requirement}</span>
              </li>
            ))}
          </ol>
        ) : 'none'],
        ['Sources', exposure.sources.map(source => <div key={source}>{fieldIdText(source)}</div>)],
        ['Labels', exposure.labels.length ? <span key="labels" className="flex flex-wrap gap-1">{exposure.labels
          .map(label => <Badge key={label} variant="outline">{label}</Badge>)}</span> : undefined],
      ]} />
      {exposure.field && (
        <Button variant="outline" size="sm" className="self-start"
          onClick={() => showLineage(exposure.service, exposure.ingress, exposure.field)}>
          <GitBranch /> Show its lineage
        </Button>
      )}
    </div>
  );
}

function nodeDetails(model: Model, qid: string): Content {
  const node = model.node(qid);
  if (!node) {
    return { kind: 'Unknown', title: qid, rows: [['Note', 'Not in this graph']] };
  }
  const service = serviceOf(qid);
  // The node's id is in the raw JSON below; the rows say what it is.
  const common: [string, ReactNode][] = [['Service', service]];
  switch (node.type) {
    case 'ingress': {
      const endpoint = model.endpointExposure(qid);
      return { kind: 'Ingress', title: endpointText(node), raw: node, rows: [...common,
        ['Handler', <CodeRefText key="handler" target={node.handler} />],
        ['Response', node.response && `${node.response.type}${node.response.many ? ' (a collection)' : ''}`],
        ['Receives', payload(node.request)],
        ['Endpoint requires', endpoint && <Requires key="requires" text={endpoint.requirement} />],
        ['Steps on its path', model.path(qid).length],
        ['Called by', model.linksTo(qid).map(link => (
          <div key={link.from}><NodeLink qid={link.from}>{nodeLabel(model, link.from)}</NodeLink>
            <span className="text-muted-foreground"> ({linkKind(link)})</span></div>
        ))],
      ] };
    }
    case 'location': {
      const observation = model.observation(qid);
      const source = model.graphs.get(service)?.authoritySource;
      const never = untraced(node);
      return { kind: `${SCOPES[node.scope]?.label ?? node.scope} check`, title: node.mechanism, raw: node, rows: [...common,
        ['Requirement', <span key="req" className="font-mono text-xs font-semibold">{requirementText(node.requirement)}</span>],
        ['Written as', node.requirement?.expression && <Code key="expr">{node.requirement.expression}</Code>],
        ['Scope', SCOPES[node.scope]?.title ?? node.scope],
        ['Phase', node.phase === 'POST' ? 'POST: after the method returns, on its result' : 'PRE: before the code runs'],
        ['Guards field', node.field],
        ['Route pattern', node.routePattern && <Code key="route">{node.routePattern}</Code>],
        ['Code', <CodeRefText key="code" target={node.target} />],
        ['When denied', node.denial && `${DENIALS[node.denial.kind]?.title ?? node.denial.kind}`
          + (node.denial.handler ? ` (${node.denial.handler})` : '')],
        ['Proxied', node.proxied ? 'yes: applied through Spring\'s proxy, so calls on this skip it' : 'no'],
        ['Observed', observation ? `${observation.count} evaluations: ${observation.granted} granted, ${observation.denied} denied`
          : !model.observed ? 'no traces in this graph'
            : never ? `never: ${never.reason}`
              : 'not seen in the traces'],
        ['Authorities', authorityText(source).replace(/^Authorities from /, '') || undefined],
      ] };
    }
    case 'egress':
      return { kind: 'Egress', title: `${node.httpMethod} ${node.uriTemplate}`, raw: node, rows: [...common,
        ['Client', node.client],
        ['Credentials', node.credentials ? <div key="cred">{CREDENTIALS[node.credentials]?.title ?? node.credentials}
          {node.credentialsVia && <div className="text-xs text-muted-foreground">from {node.credentialsVia}</div>}</div>
          : BROKERS.has(node.httpMethod) ? NO_CALLER.title : undefined],
        ['Token', node.registration && <div key="token">{`As client ${node.registration.clientId ?? '(not set)'}`
          + ` (registration ${node.registration.id}), with ${node.registration.scopes?.length
            ? `the scopes ${node.registration.scopes.join(', ')}` : 'no scopes'}`}
          {(node.registration.tokenUri ?? node.registration.issuerUri) && <div className="text-xs text-muted-foreground">
            from {node.registration.tokenUri ?? node.registration.issuerUri}</div>}</div>],
        ['Base URL', node.baseUrl],
        ['Configured as', node.baseUrlExpression && <Code key="expr">{node.baseUrlExpression}</Code>],
        ['Call site', <CodeRefText key="site" target={node.callSite} />],
        ['Sends', payload(node.request)],
        ['Response', payload(node.response)],
        ['Links', model.linksFrom(qid).length ? model.linksFrom(qid).map(link => (
          <div key={link.to}><NodeLink qid={link.to}>{nodeLabel(model, link.to)}</NodeLink>
            <span className="text-muted-foreground"> ({linkKind(link)})</span></div>
        )) : 'none: no linked service matches this call'],
      ] };
    case 'field': {
      const flowsOf = (direction: 'from' | 'to') => model.system.services.flatMap(graph => graph.flows
        .map(flow => ({ ...flow, from: qualify(graph.service, flow.from), to: qualify(graph.service, flow.to) })))
        .concat(model.system.flows).filter(flow => flow[direction] === qid);
      const unique = (flows: Flow[], side: 'from' | 'to') =>
        [...new Map(flows.map(flow => [`${flow[side]}|${flow.source}|${flow.kind}`, flow])).values()];
      const describe = (flow: Flow, other: 'from' | 'to') => (
        <div key={flow[other] + flow.source}>
          <span className="text-muted-foreground">{flow.source.toLowerCase()}{flow.kind === 'NETWORK' ? ' network' : ''} </span>
          <NodeLink qid={flow[other]}>{fieldIdText(flow[other])}</NodeLink>
        </div>
      );
      return { kind: 'Field', title: node.name, raw: node, rows: [...common,
        ['Owner', <Code key="owner">{node.owner}</Code>],
        ['JSON name', node.jsonName],
        ['Java type', node.javaType],
        ['Labels', (node.labels ?? []).join(', ')],
        ['Declassified', node.declassified ? 'yes: a Provided fact says it no longer inherits its sources\' sensitivity'
          + ' and requirements' : undefined],
        ['Guarded by', model.guardsOf(qid).map(guard => {
          const check = model.node(guard);
          return check?.type === 'location' && (
            <div key={guard}><Code>{requirementText(check.requirement)}</Code>
              <span className="text-muted-foreground"> ({check.mechanism}, {DENIALS[check.denial?.kind ?? 'THROW']?.label}
                {' '}when denied)</span></div>
          );
        })],
        ['Comes from', unique(flowsOf('to'), 'from').map(flow => describe(flow, 'from'))],
        ['Flows into', unique(flowsOf('from'), 'to').map(flow => describe(flow, 'to'))],
      ] };
    }
    case 'opaque':
      return { kind: 'Opaque call path', title: node.reason, raw: node, rows: [...common,
        ['Site', <CodeRefText key="site" target={node.site} />]] };
    default:
      // A node type newer than this UI: its raw JSON still shows.
      return { kind: 'Node', title: nodeOf(qid), raw: node, rows: common };
  }
}

/** A node as a person reads it: its service, and the endpoint or call it is. */
function nodeLabel(model: Model, qid: string): string {
  const node = model.node(qid);
  const service = serviceOf(qid);
  switch (node?.type) {
    case 'ingress':
      return `${service} ${endpointText(node)}`;
    case 'egress':
      return `${service} ${node.client} ${node.httpMethod} ${node.uriTemplate}`;
    default:
      return qid;
  }
}

function linkKind(link: Edge): string {
  return link.kind === 'NETWORK_OBSERVED' ? 'observed' : 'inferred';
}

function edgeDetails(service: string, edge: Edge): Content {
  return { kind: 'Local call path', title: `Step ${edge.order}`, raw: edge, rows: [
    ['Service', service],
    ['Path of', <Code key="path">{edge.path}</Code>],
    ['From', <Code key="from">{edge.from}</Code>],
    ['To', <Code key="to">{edge.to}</Code>],
    ['On', edge.conditional ? 'some branches only: it doesn\'t count for the endpoint on its own' : 'every way through'],
    ['Via', edge.via.length ? <ol key="via" className="list-decimal pl-4">{edge.via.map(method => <li key={method}>
      <Code>{method}</Code></li>)}</ol> : 'directly'],
  ] };
}

function linkDetails(model: Model, link: Edge): Content {
  const seen = model.linkObservation(link);
  return { kind: 'Network link', title: linkKind(link), raw: link, rows: [
    ['From egress', <NodeLink key="from" qid={link.from}>{nodeLabel(model, link.from)}</NodeLink>],
    ['To ingress', <NodeLink key="to" qid={link.to}>{nodeLabel(model, link.to)}</NodeLink>],
    ['Kind', link.kind === 'NETWORK_OBSERVED' ? 'Network-observed: a trace showed this call'
      : 'Network-inferred: matched statically (URL template and port, GraphQL operation, gRPC method, or topic or '
        + 'queue), not seen in a trace yet'],
    ['Seen', seen ? `${count(seen.count, 'call')} in the traces` : undefined],
    ['Direction', link.bidirectional ? 'both ways: arguments out, response back' : 'one way'],
  ] };
}

function flowDetails(flow: Flow): Content {
  return { kind: `${flow.kind.toLowerCase()} flow`, title: flow.source.toLowerCase(), raw: flow, rows: [
    ['From', <Code key="from">{flow.from}</Code>],
    ['To', <Code key="to">{flow.to}</Code>],
    ['Field source', FIELD_SOURCES[flow.source]],
    ['Part of', flow.path && <Code key="path">{flow.path}</Code>],
  ] };
}
