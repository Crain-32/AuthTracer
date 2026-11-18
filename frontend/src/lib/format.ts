// @supports FINDINGS_VIEW, DIFF_VIEW, LEGEND_VIEW, UI
import { nodeOf, serviceOf } from './model';
import type { AuthoritySource, CodeRef, IngressNode, LocationNode, Payload, Requirement } from './types';

/** dev.crain.profileservice.admin.CompensationController$CompensationView -> CompensationController.CompensationView */
export function shortClass(name: string | undefined): string {
  return name ? name.slice(name.lastIndexOf('.') + 1).replaceAll('$', '.') : '';
}

/** findAll(int) -> findAll; a bare name (an inherited repository method) stays as it is. */
function methodName(method: string): string {
  const paren = method.indexOf('(');
  return paren < 0 ? method : method.slice(0, paren);
}

/** BYPASSED -> Bypassed, DIAGONAL_ESCALATION -> Diagonal escalation. */
export function kindTitle(kind: string): string {
  const words = kind.toLowerCase().replaceAll('_', ' ');
  return words.charAt(0).toUpperCase() + words.slice(1);
}

/** dev.crain.employeeservice.employee.Employee#getSalary() -> Employee#getSalary(), in running text. */
export function shortNames(text: string | undefined | null): string {
  return String(text ?? '').replace(/\b(?:[a-z_][a-z0-9_]*\.)+([A-Z][\w$]*)/g, '$1');
}

/** GRPC fixtures.grpc.Greeter/SayHello -> Greeter/SayHello: on a node the package is noise; the tooltip keeps it. */
export function shortRoute(method: string, route: string | undefined): string {
  const text = route ?? '';
  return method === 'GRPC' ? text.replace(/^[\w.]*\.(?=\w+\/)/, '') : text;
}

/** EmployeeService#find:23 */
export function codeRef(ref: CodeRef | undefined): string {
  if (!ref) {
    return '';
  }
  return shortClass(ref.className) + (ref.method ? '#' + methodName(ref.method) : '') + (ref.line ? ':' + ref.line : '');
}

/** dev.crain.Foo#find(long) -> Foo#find */
export function methodKey(key: string): string {
  const [className, method] = key.split('#');
  return codeRef({ className, method });
}

export function fullCodeRef(ref: CodeRef | undefined): string {
  if (!ref) {
    return '';
  }
  return ref.className + (ref.method ? '#' + ref.method : '') + (ref.line ? ', line ' + ref.line : '');
}

export function payload(body: Payload | undefined): string {
  return body ? shortClass(body.type) + (body.many ? '[]' : '') : '';
}

/** An Ingress as it reads: GET /user/messages, with the params its mapping requires. */
export function endpointText(ingress: Pick<IngressNode, 'httpMethod' | 'route' | 'params'>): string {
  return `${ingress.httpMethod} ${ingress.route}${ingress.params ? `?${ingress.params}` : ''}`;
}

/** One Location's requirement as text. The effective requirement of a path comes from the server. */
export function requirementText(requirement: Requirement | undefined, nested = false): string {
  if (!requirement) {
    return 'none';
  }
  const operands = (requirement.operands ?? []).map(operand => requirementText(operand, true));
  const texts: Partial<Record<string, string>> = {
    PERMIT_ALL: 'permitAll',
    AUTHENTICATED: 'authenticated',
    FULLY_AUTHENTICATED: 'fullyAuthenticated',
    REMEMBER_ME: 'rememberMe',
    ANONYMOUS: 'anonymous',
    DENY_ALL: 'denyAll',
    ANY_AUTHORITY: (requirement.authorities ?? []).join(' or '),
    ALL_AUTHORITIES: (requirement.authorities ?? []).join(' and '),
    AND: operands.join(' and '),
    OR: operands.join(' or '),
    NOT: 'not ' + operands[0],
  };
  const read = texts[requirement.kind] ?? requirement.expression ?? requirement.kind;
  // Custom code AuthTracer couldn't reduce says who decides it.
  const text = requirement.kind === 'EXPRESSION' && requirement.decidedBy
    ? `${read} (decided by ${codeRef(requirement.decidedBy)})` : read;
  return nested && /\s(and|or)\s/.test(text) ? `(${text})` : text;
}

/** CompensationView.salary: the innermost class and the property; owners/details: owner.pets[].name for a view. */
function fieldText(owner: string, name: string): string {
  if (owner.startsWith('view:')) {
    return `${owner.slice('view:'.length)}: ${name.replaceAll(':', '.')}`;
  }
  return `${shortClass(owner).split('.').at(-1)}.${name}`;
}

/** "employee-service Employee.ssn" for a qualified field id. */
export function fieldIdText(qualifiedFieldId: string): string {
  const id = nodeOf(qualifiedFieldId).replace(/^field:/, '');
  const parts = id.split('.');
  return `${serviceOf(qualifiedFieldId)} ${fieldText(parts.slice(0, -1).join('.'), parts.at(-1)!)}`;
}

/** Plural-aware count: 1 check, 2 checks. */
export function count(n: number, singular: string, plural = `${singular}s`): string {
  return `${n} ${n === 1 ? singular : plural}`;
}

export const SCOPES: Record<string, { label: string; title: string }> = {
  HTTP_REQUEST: { label: 'request', title: 'Request check (authorizeHttpRequests, or authorizeExchange on WebFlux, in the filter chain), before any code runs' },
  METHOD: { label: 'method', title: 'Method check (method security on a bean, through its proxy)' },
  FIELD: { label: 'field', title: 'Field check (annotation on a getter of an @AuthorizeReturnObject result)' },
};

export const DENIALS: Record<string, { label: string; title: string }> = {
  THROW: { label: 'denies', title: 'The request fails: AccessDeniedException, 403 (401 without a token)' },
  HANDLER: { label: 'masks', title: 'A custom handler replaces the value, typically with a mask. The request succeeds' },
  NULL: { label: 'nulls', title: 'The value is replaced with null. The request succeeds' },
  FILTER: { label: 'filters', title: 'Denied elements are removed from the collection. The request succeeds' },
};

/** What an egress authenticates with (decision 0021): only a relayed token makes the called service check the caller. */
export const CREDENTIALS: Record<string, { label: string; title: string }> = {
  RELAY: { label: 'token relay', title: 'Relays the caller\'s token: the called service checks the same caller, so its checks count for this endpoint\'s callers' },
  OAUTH2_CLIENT: { label: 'OAuth2', title: 'Uses a token from an OAuth2 client registration: the called service checks this service, not its callers' },
  STATIC: { label: 'fixed creds', title: 'Sends fixed credentials: the called service checks this service, not its callers' },
  NONE: { label: 'no creds', title: 'Sends no credentials AuthTracer can see: the called service checks an anonymous request' },
  UNKNOWN: { label: 'creds?', title: 'Sets credentials AuthTracer can\'t read: the called service\'s checks are not counted for this endpoint\'s callers' },
};

/** The brokers a message is sent through (decision 0044): an egress to one sends a message, not a request. */
export const BROKERS = new Set(['KAFKA', 'RABBIT', 'JMS']);

/** What a message carries instead of credentials: no caller (decision 0044). */
export const NO_CALLER = { label: 'no caller', title: 'Sends a message, which carries no caller: its listener runs with'
  + ' no one signed in, so the checks on that path don\'t count for this endpoint\'s callers' };

/** Why the traces never show a check's decisions, for the checks Spring records no decision span for. */
export function untraced(location: LocationNode): { label: string; reason: string } | undefined {
  if (location.denial?.kind === 'FILTER') {
    return { label: 'filters record no trace', reason: 'Spring Security records no decision span for filters' };
  }
  if (location.mechanism.startsWith('authorizeRequests (gRPC)')) {
    // Spring gRPC 1.1.1's GrpcSecurity observes its AuthenticationManager, not its AuthorizationManager.
    return { label: 'gRPC rules record no trace', reason: 'Spring gRPC records authentication, not its request rules' };
  }
  if (location.mechanism.startsWith('AuthorizationManager#')) {
    // Decision 0066: Spring observes the managers of its filters and interceptors, not one the code calls itself.
    return { label: 'checks in code record no trace',
      reason: 'Spring Security records decisions of its own filters and interceptors, not of a manager the code calls' };
  }
  return undefined;
}

export const FRESHNESS: Record<string, string> = {
  SNAPSHOT: 'fixed when the token was issued or the user logged in: a mid-request revocation is not honored',
  LIVE: 're-read on every request: a revocation is honored on the next check',
  UNKNOWN: 'unknown',
};

const AUTHORITY_KINDS: Record<string, string> = {
  JWT_CLAIMS: 'JWT claims',
  OPAQUE_TOKEN_INTROSPECTION: 'token introspection',
  USER_DETAILS: 'a UserDetails lookup',
  IDENTITY_PROVIDER: 'an identity provider login',
  CUSTOM_FILTER: 'a filter of the application\'s own that authenticates',
  UNKNOWN: 'an unknown source',
};

/** Where a service's authorities come from and how fresh they are; empty when the graph doesn't say. */
export function authorityText(source: AuthoritySource | undefined): string {
  if (!source) {
    return '';
  }
  const freshness = source.freshness ?? 'UNKNOWN';
  return `Authorities from ${source.detail ?? AUTHORITY_KINDS[source.kind] ?? source.kind}; `
    + `${freshness.toLowerCase()}: ${FRESHNESS[freshness] ?? ''}`;
}

export const FIELD_SOURCES: Record<string, string> = {
  DIRECT: 'Direct: the same value, possibly renamed or reassigned',
  COMPLEX: 'Complex: a structure that nests other fields',
  COMPUTED: 'Computed: a non-structural operation, e.g. concatenation, arithmetic or a branch on the value',
  MASKED: 'Masked: what a check\'s denial handler derives from the value, e.g. its last four digits, and writes in its'
    + ' place for the callers the check denies (the field named "(denied)")',
};

export const FINDING_KINDS: Record<string, string> = {
  NOT_ENFORCED: 'Looks like a check, but Spring never enforces it (method security not enabled, a private/final/static'
    + ' method, a class that is not a bean). Counts as No Authorization.',
  BYPASSED: 'Enforced in general, but skipped on this call path: a call on this, an object that is not an'
    + ' authorization proxy, a request WebSecurityCustomizer ignoring() takes out of the filter chain, or a call to'
    + ' another service with the service\'s own credentials (its checks there evaluate the service, not the caller).'
    + ' Counts as No Authorization on that path.',
  UNRECOGNIZED_CHECK: 'Hand-rolled check-like code outside Spring Security\'s mechanisms. Counts as No Authorization'
    + ' until it moves to a recognized mechanism or is declared with a Provided check fact.',
  AUTHORITIES_IN_CODE: 'Code outside a filter sets the Authentication, or its authorities, itself: the checks after it'
    + ' on that thread see what it sets, not the caller\'s, so a caller may need less than the path shows. Also a'
    + ' filter that authenticates after the request rules: they decided for a caller who had not signed in.',
  OPAQUE_CALLPATH: 'The request path goes through code the analysis cannot follow (e.g. reflection). What runs after'
    + ' it is unknown.',
  OPAQUE_CONFIG: 'Security configuration the analysis cannot read, e.g. a RoleHierarchy built at runtime. Checks it'
    + ' affects may admit more callers than the graph shows.',
  RUNTIME_ONLY_CHECK: 'Spring Security evaluated a check at runtime that the static graph does not have on that path:'
    + ' the scan missed a check.',
  UNMATCHED_CALL: 'A traced call between services matches no static egress or ingress: the scan missed a call site'
    + ' or route.',
  PROVIDED_CONFLICT: 'A local Provided fact (authtracer.yaml) lost to an Org-level fact about the same thing and was'
    + ' ignored.',
  CHECK_AFTER_COMMIT: 'A @PostAuthorize or @PostFilter check runs outside its method\'s transaction, so it decides after'
    + ' the commit: a denied caller gets an error, but what the method wrote is saved.',
  ALWAYS_DENIED: 'A check that denies every caller because of how it is configured, e.g. hasPermission(..) with no'
    + ' PermissionEvaluator, or an authority the service\'s tokens never carry (a role where its JWTs map only'
    + ' scopes): what it guards cannot be reached.',
  TOKEN_REJECTED: 'A call brings a token the called service may reject: a relayed token need not name one of the'
    + ' audiences the called service accepts; a service\'s own token carries only the scopes its client registration'
    + ' asks for, which may not be what the called path asks for, and the authorization server refuses to issue one'
    + ' with scopes its client can\'t be granted.',
  ALWAYS_GRANTED: 'A check that lets every caller through although it reads as if it asks for something: custom'
    + ' decision code that always grants (permit-all in disguise), or a role check that callers who have not signed'
    + ' in pass because the anonymous authentication carries that role.',
  OPEN_SENSITIVE_ENDPOINT: 'An endpoint a library serves that hands out secrets or control of the application'
    + ' (Actuator\'s heap dump and writes, the H2 console, a config server\'s configuration, a Eureka server\'s'
    + ' registry) answers callers who have not logged in. Ask for a role in the filter chain, or declare a Provided'
    + ' requirement if something outside the application keeps callers out.',
};

export const CHANGE_KINDS: Record<string, string> = {
  WEAKENED: 'Fewer callers are kept out of this endpoint or field than before. Fails the check.',
  DIAGONAL_ESCALATION: 'A new route to existing data that asks less than every existing route to it. Fails the check.',
  POLICY_VIOLATION: 'A field with a governed label (e.g. PII) is now exposed with less than its policy requires. Fails'
    + ' the check.',
  CHANGED: 'A sideways change the strength order cannot rank, e.g. ROLE_ADMIN to ROLE_AUDITOR. Needs review.',
  NEW_FINDING: 'The head revision has a finding the base did not. Needs review.',
  STRENGTHENED: 'More callers are kept out than before.',
  NEW_EXPOSURE: 'A new endpoint or field with no existing route to the same data to compare against.',
  REMOVED: 'An endpoint or field that no longer exists.',
};

export const SEVERITIES: Record<string, string> = {
  FAIL: 'Fails the check (exit code 1)',
  REVIEW: 'Needs a human to look (fails only with --fail-on-review)',
  INFO: 'For information',
};
