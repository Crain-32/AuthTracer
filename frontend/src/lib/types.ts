// @supports UI
/**
 * The JSON the server writes: application graphs, system graphs, exposures and diff reports (see the records in
 * dev.crain.authtracer.graph, api and diff).
 */

export interface CodeRef {
  className: string;
  method?: string;
  line?: number;
}

export type RequirementKind = 'PERMIT_ALL' | 'AUTHENTICATED' | 'FULLY_AUTHENTICATED' | 'REMEMBER_ME' | 'ANONYMOUS'
  | 'ANY_AUTHORITY' | 'ALL_AUTHORITIES' | 'DENY_ALL' | 'AND' | 'OR' | 'NOT' | 'EXPRESSION';

export interface Requirement {
  kind: RequirementKind;
  authorities?: string[];
  operands?: Requirement[];
  expression?: string;
  /** The application code that decides it: a custom AuthorizationManager, a SpEL bean's method, a PermissionEvaluator. */
  decidedBy?: CodeRef;
}

export interface Payload {
  type: string;
  many: boolean;
  views?: string[];
}

export type Scope = 'HTTP_REQUEST' | 'METHOD' | 'FIELD';
export type DenialKind = 'THROW' | 'HANDLER' | 'NULL' | 'FILTER';
export type CredentialsKind = 'RELAY' | 'OAUTH2_CLIENT' | 'STATIC' | 'NONE' | 'UNKNOWN';

export interface IngressNode {
  type: 'ingress';
  id: string;
  httpMethod: string;
  route: string;
  params?: string;
  handler?: CodeRef;
  response?: Payload;
  /** What a message listener receives. */
  request?: Payload;
}

export interface EgressNode {
  type: 'egress';
  id: string;
  client: string;
  httpMethod: string;
  uriTemplate: string;
  baseUrl?: string;
  baseUrlExpression?: string;
  callSite?: CodeRef;
  response?: Payload;
  /** What a message send sends. */
  request?: Payload;
  credentials?: CredentialsKind;
  credentialsVia?: string;
  /** The OAuth2 client registration whose own token the call sends, as the service's properties declare it. */
  registration?: Registration;
}

export interface Registration {
  id: string;
  clientId?: string;
  grantType?: string;
  scopes?: string[];
  tokenUri?: string;
  issuerUri?: string;
}

export interface LocationNode {
  type: 'location';
  id: string;
  mechanism: string;
  scope: Scope;
  phase: 'PRE' | 'POST';
  requirement?: Requirement;
  target: CodeRef;
  field?: string;
  routePattern?: string;
  denial?: { kind: DenialKind; handler?: string };
  proxied?: boolean;
  fieldOwner?: string;
  /** LIVE when the code that decides the check reads a store or another service on every call. */
  freshness?: 'SNAPSHOT' | 'LIVE' | 'UNKNOWN';
  /** The method's parameters its expression names (#id), with what the request binds into them (decision 0091). */
  arguments?: { name: string; parameter?: number; binding?: string }[];
  /** The token claims its expression reads (decision 0091). */
  claims?: string[];
}

export interface FieldNode {
  type: 'field';
  id: string;
  owner: string;
  name: string;
  jsonName?: string;
  javaType?: string;
  labels?: string[];
  declassified?: boolean;
  views?: string[];
  graphQl?: boolean;
}

export interface OpaqueNode {
  type: 'opaque';
  id: string;
  reason: string;
  site?: CodeRef;
}

export type GraphNode = IngressNode | EgressNode | LocationNode | FieldNode | OpaqueNode;

export interface Edge {
  from: string;
  to: string;
  kind: 'LOCAL' | 'NETWORK_OBSERVED' | 'NETWORK_INFERRED';
  path?: string;
  order: number;
  via: string[];
  bidirectional: boolean;
  conditional?: boolean;
}

export interface Flow {
  path?: string;
  from: string;
  to: string;
  source: 'DIRECT' | 'COMPLEX' | 'COMPUTED' | 'MASKED';
  kind: 'LOCAL' | 'NETWORK';
}

export interface Finding {
  kind: string;
  message: string;
  location?: CodeRef;
}

export interface ProvidedFact {
  kind: string;
  subject: string;
  labels?: string[];
  requirement?: string;
  reason?: string;
  origin: string;
  fresh?: boolean;
}

export interface AuthoritySource {
  kind: string;
  freshness: 'SNAPSHOT' | 'LIVE' | 'UNKNOWN';
  detail?: string;
  /** The only authorities a request can carry (SCOPE_* for a prefix), when the scan can tell. */
  granted?: string[];
  /** What a resource server reads from its JWTs: claims as authorities, accepted audiences. */
  jwt?: {
    authorities?: { claims: string[]; expression?: string; prefix?: string; delimiter?: string }[];
    audiences?: string[];
    validators?: string[];
    unread?: string[];
    rewritten?: string[];
  };
}

export interface ApplicationGraph {
  schemaVersion: number;
  service: string;
  revision: string;
  port?: number;
  additionalPorts?: number[];
  authoritySource?: AuthoritySource;
  nodes: GraphNode[];
  edges: Edge[];
  flows: Flow[];
  provided?: ProvidedFact[];
  findings: Finding[];
  /** What an authorization server issues tokens with: each client's scopes, the claims customizers add. */
  issuer?: {
    clients?: Record<string, string[]>;
    claims?: string[];
    unread?: string[];
  };
}

export interface Observation {
  subject: string;
  kind: 'LOCATION' | 'LINK';
  count: number;
  granted: number;
  denied: number;
}

export interface IdentityUsage {
  authorities: string[];
  authenticationType: string;
  requests: number;
  endpoints: string[];
  needed: string[];
  unneeded: string[];
  denied: number;
  unread: number;
}

export interface SystemGraph {
  schemaVersion: number;
  services: ApplicationGraph[];
  links: Edge[];
  flows: Flow[];
  observations: Observation[];
  identities: IdentityUsage[];
  findings: Finding[];
}

export interface ExposureStep {
  location: string;
  mechanism: string;
  scope?: Scope;
  requirement: string;
  guards?: string;
}

export interface Violation {
  label: string;
  requires: string;
  reason?: string;
}

/** One row of /api/exposures: an endpoint (field '') or one of its response fields. */
export interface Exposure {
  service: string;
  ingress: string;
  endpoint: string;
  field: string;
  fieldId: string;
  requirement: string;
  adds: string | null;
  steps: ExposureStep[];
  sources: string[];
  labels: string[];
  lineage: Flow[];
  violations?: Violation[];
}

export type Severity = 'FAIL' | 'REVIEW' | 'INFO';

export interface Change {
  kind: string;
  severity: Severity;
  service: string;
  /** Left out when empty: a new finding with no location. */
  endpoint?: string;
  field?: string;
  before?: string | null;
  after?: string | null;
  labels?: string[];
  message?: string;
}

export interface DiffReport {
  base: string;
  head: string;
  changes: Change[];
}

/** A stored graph, as /api/graphs lists them. */
export interface Snapshot {
  id: number;
  kind: 'APPLICATION' | 'SYSTEM';
  service: string;
  revision?: string;
  createdAt: string;
}
