// @supports PATHS_VIEW
import { BROKERS, CREDENTIALS, codeRef, endpointText, NO_CALLER, payload, requirementText, shortRoute, untraced }
  from '@/lib/format';
import { nodeOf, type Model } from '@/lib/model';
import type { DenialKind, LocationNode, Observation, Scope } from '@/lib/types';

export type StepKind = 'ingress' | 'egress' | 'check' | 'opaque';

/** How one step reads on a diagram; the details panel has the rest. */
export interface StepSpec {
  qid: string;
  kind: StepKind;
  scope?: Scope;
  /** For an ingress or egress: GET, POST, KAFKA, GRPC, ... */
  method?: string;
  head: string;
  main: string;
  denial?: DenialKind;
  credentials?: string;
  observation?: Observation | 'unseen' | 'untraced';
  /** For a check Spring records no decision span for, why its decisions are not in the traces. */
  untraced?: string;
  tooltip: string;
}

export function stepSpec(model: Model, qid: string): StepSpec {
  const node = model.node(qid);
  switch (node?.type) {
    case 'ingress':
      return { qid, kind: 'ingress', method: node.httpMethod, head: 'Ingress', main: shortRoute(node.httpMethod, node.route)
        + (node.params ? `?${node.params}` : ''),
      tooltip: `${endpointText(node)}\n${codeRef(node.handler)}${node.response ? ` → ${payload(node.response)}` : ''}` };
    case 'egress': {
      // A message has no base URL and no credentials: it carries no caller.
      const message = !node.credentials && BROKERS.has(node.httpMethod);
      const credentials = node.credentials ? CREDENTIALS[node.credentials] : message ? NO_CALLER : undefined;
      return { qid, kind: 'egress', method: node.httpMethod, head: node.client,
        main: shortRoute(node.httpMethod, node.uriTemplate), credentials: credentials?.label,
        tooltip: `${node.client} ${node.httpMethod} ${node.uriTemplate}` + (message ? ''
          : `\n${node.baseUrl ?? node.baseUrlExpression ?? 'base URL unknown'}`)
          + (credentials ? `\n${credentials.title}${node.credentialsVia ? ` (${node.credentialsVia})` : ''}` : '')
          + `\n${codeRef(node.callSite)}` };
    }
    case 'location':
      return { qid, kind: 'check', scope: node.scope, head: checkHead(node), main: requirementText(node.requirement),
        denial: node.denial?.kind === 'THROW' ? undefined : node.denial?.kind, observation: observation(model, qid, node),
        untraced: untraced(node)?.label,
        tooltip: `${node.mechanism} (${node.scope}, ${node.phase})\n${node.requirement?.expression
          ?? requirementText(node.requirement)}\n${reads(node)}${node.routePattern ? `${node.routePattern} · ` : ''}`
          + codeRef(node.target) };
    case 'opaque':
      return { qid, kind: 'opaque', head: 'Opaque', main: node.reason, tooltip: `${node.reason}\n${codeRef(node.site)}` };
    default:
      return { qid, kind: 'opaque', head: 'Unknown node', main: nodeOf(qid), tooltip: qid };
  }
}

/** What a check's expression reads besides authorities, one line each: the method's arguments, the token's claims. */
function reads(location: LocationNode): string {
  const lines: string[] = [];
  if (location.arguments?.length) {
    lines.push('Reads ' + location.arguments.map((argument) => `#${argument.name} (${argument.parameter === undefined
      ? 'null: no parameter of that name' : argument.binding ?? `parameter ${argument.parameter + 1}`})`).join(', '));
  }
  if (location.claims?.length) {
    lines.push(`Token claims ${location.claims.join(', ')}`);
  }
  return lines.map((line) => line + '\n').join('');
}

/** Checks Spring records no decision span for (filters, Spring gRPC's rules) are never observed. */
function observation(model: Model, qid: string, location: LocationNode): StepSpec['observation'] {
  const seen = model.observation(qid);
  if (seen || !model.observed) {
    return seen;
  }
  return untraced(location) ? 'untraced' : 'unseen';
}

/** A STOMP message rule by its destinations (the Ingress already says MESSAGE or SUBSCRIBE). */
function messageRule(location: LocationNode): string {
  if (!location.routePattern) {
    return 'No message rule';
  }
  return 'Message rule ' + location.routePattern.replace(/^simp\w*Matchers\((.*)\)$/, '$1');
}

/** An RSocket rule by its matcher: the connection's setup, or the route (decision 0045). */
function rsocketRule(location: LocationNode): string {
  if (!location.routePattern) {
    return location.mechanism.includes('the setup') ? 'No RSocket setup rule' : 'No RSocket rule';
  }
  return location.routePattern === 'setup()' ? 'RSocket setup'
    : 'RSocket rule ' + location.routePattern.replace(/^route\((.*)\)$/, '$1');
}

/** A short name for the check: the color already says request, method or field. */
export function checkHead(location: LocationNode): string {
  const after = location.phase === 'POST' ? ' · after' : '';
  if (location.scope === 'HTTP_REQUEST') {
    const mechanism = location.mechanism;
    const pattern = mechanism.includes('(gRPC)') ? shortRoute('GRPC', location.routePattern) : location.routePattern;
    const name = /^(authorize(HttpRequests|Exchange|Requests)|intercept-url)/.test(mechanism) ? `Rule ${pattern}`
      : mechanism.includes('ignoring()') ? `ignoring() ${location.routePattern}`
        : mechanism.startsWith('Spring Boot default') ? 'Boot default rule'
          : mechanism.startsWith('Spring Security default') ? 'Default rule'
            : mechanism.startsWith('Provided') ? 'Provided rule'
              : mechanism.startsWith('Transports of') ? 'HTTP or WebSocket'
                : mechanism.startsWith('Message authorization') ? messageRule(location)
                  : mechanism.startsWith('authorizePayload') ? rsocketRule(location)
                    : mechanism.startsWith('AuthenticationWebSocketInterceptor') ? 'WebSocket auth' : mechanism;
    return name + after;
  }
  if (location.fieldOwner) {
    // A GraphQL resolver's checks, on the type's field; the tooltip names the resolver.
    return `${location.fieldOwner.slice(location.fieldOwner.lastIndexOf('.') + 1)}.${location.field}` + after;
  }
  return (location.scope === 'FIELD' ? `${location.field} · ${location.mechanism}` : location.mechanism) + after;
}
