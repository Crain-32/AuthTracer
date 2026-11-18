import { describe, expect, it } from 'vitest';

import { Model } from '@/lib/model';
import type { GraphNode, LocationNode, Observation } from '@/lib/types';
import { app, model, system } from '@/test/graphs';

import { checkHead, stepSpec } from './stepSpec';

const rule = (mechanism: string, routePattern?: string, more: Partial<LocationNode> = {}): LocationNode => ({
  type: 'location', id: 'location:rule', mechanism, scope: 'HTTP_REQUEST', phase: 'PRE', routePattern,
  target: { className: 'x.SecurityConfig', method: 'filterChain(HttpSecurity)', line: 12 }, ...more });

/** A one-service model with these nodes, and these check decisions in its traces. */
function modelOf(nodes: GraphNode[], observations: Observation[] = []): Model {
  const linked = system([app('a', nodes)]);
  linked.observations = observations;
  return new Model(linked, [], 'test');
}

describe('stepSpec', () => {
  it('reads an ingress by its route and params, its handler and response in the tooltip', () => {
    const m = modelOf([{ type: 'ingress', id: 'ingress:GRPC fixtures.grpc.Greeter/SayHello', httpMethod: 'GRPC',
      route: 'fixtures.grpc.Greeter/SayHello', handler: { className: 'x.Greeter', method: 'sayHello(Request)', line: 9 },
      response: { type: 'x.Reply', many: true } }, { type: 'ingress', id: 'ingress:GET /owners', httpMethod: 'GET',
      route: '/owners', params: 'lastName' }]);
    expect(stepSpec(m, 'a/ingress:GRPC fixtures.grpc.Greeter/SayHello')).toEqual({ qid: 'a/ingress:GRPC fixtures.grpc.Greeter/SayHello',
      kind: 'ingress', method: 'GRPC', head: 'Ingress', main: 'Greeter/SayHello',
      tooltip: 'GRPC fixtures.grpc.Greeter/SayHello\nGreeter#sayHello:9 → Reply[]' });
    expect(stepSpec(m, 'a/ingress:GET /owners')).toMatchObject({ main: '/owners?lastName',
      tooltip: 'GET /owners?lastName\n' });
  });

  it('reads an egress by its client and URI, with what it authenticates with', () => {
    const m = modelOf([
      { type: 'egress', id: 'egress:relay', client: 'RestClient', httpMethod: 'GET', uriTemplate: '/employees/{id}',
        baseUrl: 'http://employee-service', credentials: 'RELAY', credentialsVia: 'BearerTokenInterceptor',
        callSite: { className: 'x.Employees', method: 'find(long)', line: 30 } },
      { type: 'egress', id: 'egress:configured', client: 'WebClient', httpMethod: 'POST', uriTemplate: '/audit',
        baseUrlExpression: '${audit.url}', credentials: 'STATIC' },
      { type: 'egress', id: 'egress:plain', client: 'RestTemplate', httpMethod: 'GET', uriTemplate: '/x' },
    ]);
    expect(stepSpec(m, 'a/egress:relay')).toEqual({ qid: 'a/egress:relay', kind: 'egress', method: 'GET', head: 'RestClient',
      main: '/employees/{id}', credentials: 'token relay', tooltip: 'RestClient GET /employees/{id}\nhttp://employee-service\n'
        + 'Relays the caller\'s token: the called service checks the same caller, so its checks count for this'
        + ' endpoint\'s callers (BearerTokenInterceptor)\nEmployees#find:30' });
    expect(stepSpec(m, 'a/egress:configured').tooltip).toBe('WebClient POST /audit\n${audit.url}\nSends fixed credentials:'
      + ' the called service checks this service, not its callers\n');
    expect(stepSpec(m, 'a/egress:plain')).toMatchObject({ credentials: undefined,
      tooltip: 'RestTemplate GET /x\nbase URL unknown\n' });
  });

  it('reads a message sent to a broker as carrying no caller, with no base URL', () => {
    const m = modelOf([{ type: 'egress', id: 'egress:kafka', client: 'KafkaTemplate', httpMethod: 'KAFKA',
      uriTemplate: 'orders', callSite: { className: 'x.Orders', method: 'place(Order)', line: 7 } }]);
    expect(stepSpec(m, 'a/egress:kafka')).toMatchObject({ head: 'KafkaTemplate', main: 'orders', credentials: 'no caller',
      tooltip: 'KafkaTemplate KAFKA orders\nSends a message, which carries no caller: its listener runs with no one'
        + ' signed in, so the checks on that path don\'t count for this endpoint\'s callers\nOrders#place:7' });
  });

  it('reads a check by its requirement; only a denial that keeps the request going is named', () => {
    const m = modelOf([
      rule('authorizeHttpRequests', '/admin/**', { requirement: { kind: 'ANY_AUTHORITY', authorities: ['ROLE_ADMIN'] },
        denial: { kind: 'THROW' } }),
      { type: 'location', id: 'location:mask', mechanism: '@PreAuthorize', scope: 'FIELD', phase: 'POST', field: 'ssn',
        requirement: { kind: 'EXPRESSION', expression: 'hasRole(\'ADMIN\')' }, denial: { kind: 'HANDLER', handler: 'Mask' },
        target: { className: 'x.Employee', method: 'getSsn()' } },
    ]);
    expect(stepSpec(m, 'a/location:rule')).toEqual({ qid: 'a/location:rule', kind: 'check', scope: 'HTTP_REQUEST',
      head: 'Rule /admin/**', main: 'ROLE_ADMIN', denial: undefined, observation: undefined,
      tooltip: 'authorizeHttpRequests (HTTP_REQUEST, PRE)\nROLE_ADMIN\n/admin/** · SecurityConfig#filterChain:12' });
    expect(stepSpec(m, 'a/location:mask')).toMatchObject({ head: 'ssn · @PreAuthorize · after', main: 'hasRole(\'ADMIN\')',
      denial: 'HANDLER', tooltip: '@PreAuthorize (FIELD, POST)\nhasRole(\'ADMIN\')\nEmployee#getSsn' });
  });

  it('lists what a check\'s expression reads: the arguments with their bindings, and the token\'s claims', () => {
    const m = modelOf([{ ...rule('@PreAuthorize'), id: 'location:read', scope: 'METHOD',
      requirement: { kind: 'EXPRESSION', expression: '#id == principal.claims[\'owner\'] and #tag != null' },
      arguments: [{ name: 'id', parameter: 0, binding: 'path variable id' }, { name: 'p1', parameter: 1 },
        { name: 'tag' }], claims: ['owner'] }]);
    expect(stepSpec(m, 'a/location:read').tooltip).toBe('@PreAuthorize (METHOD, PRE)\n'
      + '#id == principal.claims[\'owner\'] and #tag != null\n'
      + 'Reads #id (path variable id), #p1 (parameter 2), #tag (null: no parameter of that name)\n'
      + 'Token claims owner\nSecurityConfig#filterChain:12');
  });

  it('says how often the traces saw a check decide, that they never did, or that filters leave no trace', () => {
    const seen: Observation = { subject: 'a/location:seen', kind: 'LOCATION', count: 3, granted: 2, denied: 1 };
    const filter: LocationNode = { ...rule('@PostFilter'), id: 'location:filter', scope: 'METHOD', denial: { kind: 'FILTER' } };
    const grpc: LocationNode = { ...rule('authorizeRequests (gRPC)'), id: 'location:grpc' };
    const verify: LocationNode = { ...rule('AuthorizationManager#verify'), id: 'location:verify', scope: 'METHOD' };
    const nodes = [{ ...rule('@PreAuthorize'), id: 'location:seen' }, { ...rule('@PreAuthorize'), id: 'location:unseen' },
      filter, grpc, verify];
    const traced = modelOf(nodes, [seen]);
    expect(stepSpec(traced, 'a/location:seen').observation).toBe(seen);
    expect(stepSpec(traced, 'a/location:unseen').observation).toBe('unseen');
    expect(stepSpec(traced, 'a/location:filter')).toMatchObject({ observation: 'untraced',
      untraced: 'filters record no trace' });
    // Spring gRPC observes authentication only.
    expect(stepSpec(traced, 'a/location:grpc')).toMatchObject({ observation: 'untraced',
      untraced: 'gRPC rules record no trace' });
    // A check the code makes with a manager of its own.
    expect(stepSpec(traced, 'a/location:verify')).toMatchObject({ observation: 'untraced',
      untraced: 'checks in code record no trace' });
    expect(stepSpec(modelOf(nodes), 'a/location:unseen').observation).toBeUndefined();
  });

  it('reads an opaque step by its reason, and a node it doesn\'t know by its id', () => {
    const m = model([app('a', [{ type: 'opaque', id: 'opaque:1', reason: 'Reflection (Method.invoke)',
      site: { className: 'x.Dispatcher', method: 'call()', line: 4 } }, { type: 'field', id: 'field:x.A.b', owner: 'x.A',
      name: 'b' }])]);
    expect(stepSpec(m, 'a/opaque:1')).toEqual({ qid: 'a/opaque:1', kind: 'opaque', head: 'Opaque',
      main: 'Reflection (Method.invoke)', tooltip: 'Reflection (Method.invoke)\nDispatcher#call:4' });
    expect(stepSpec(m, 'a/opaque:gone')).toEqual({ qid: 'a/opaque:gone', kind: 'opaque', head: 'Unknown node',
      main: 'opaque:gone', tooltip: 'a/opaque:gone' });
    expect(stepSpec(m, 'a/field:x.A.b').head).toBe('Unknown node');
  });
});

describe('checkHead', () => {
  it('names a request rule by its matcher, and the chain\'s own rules by where they come from', () => {
    expect(checkHead(rule('authorizeHttpRequests', '/owners/**'))).toBe('Rule /owners/**');
    expect(checkHead(rule('authorizeExchange', '/api/**'))).toBe('Rule /api/**');
    expect(checkHead(rule('intercept-url', '/x'))).toBe('Rule /x');
    expect(checkHead(rule('authorizeRequests (gRPC)', 'fixtures.grpc.Greeter/*'))).toBe('Rule Greeter/*');
    expect(checkHead(rule('WebSecurityCustomizer ignoring() (skips the filter chain)', '/static/**')))
      .toBe('ignoring() /static/**');
    expect(checkHead(rule('Spring Boot default SecurityFilterChain'))).toBe('Boot default rule');
    expect(checkHead(rule('Spring Security default SecurityWebFilterChain'))).toBe('Default rule');
    expect(checkHead(rule('Provided requirement (authtracer.yaml)'))).toBe('Provided rule');
    expect(checkHead(rule('Transports of POST /graphql'))).toBe('HTTP or WebSocket');
    expect(checkHead(rule('AuthenticationWebSocketInterceptor (GraphQL over WebSocket)'))).toBe('WebSocket auth');
    expect(checkHead(rule('Some newer chain rule'))).toBe('Some newer chain rule');
    expect(checkHead(rule('authorizeHttpRequests', '/x', { phase: 'POST' }))).toBe('Rule /x · after');
  });

  it('names a STOMP message rule by its destinations', () => {
    expect(checkHead(rule('Message authorization (STOMP)', 'simpDestMatchers(/app/chat)'))).toBe('Message rule /app/chat');
    expect(checkHead(rule('Message authorization (STOMP)'))).toBe('No message rule');
  });

  it('names an RSocket rule by the setup or its route', () => {
    expect(checkHead(rule('authorizePayload (RSocket)', 'setup()'))).toBe('RSocket setup');
    expect(checkHead(rule('authorizePayload (RSocket)', 'route(orders.*)'))).toBe('RSocket rule orders.*');
    expect(checkHead(rule('authorizePayload (RSocket) (no rule matched the setup: denied)'))).toBe('No RSocket setup rule');
    expect(checkHead(rule('authorizePayload (RSocket) (no rule matched the request: denied)'))).toBe('No RSocket rule');
  });

  it('names a method check by its mechanism, a field check by its field, a resolver\'s by the type\'s field', () => {
    const method = rule('@PreAuthorize', undefined, { scope: 'METHOD' });
    expect(checkHead(method)).toBe('@PreAuthorize');
    expect(checkHead({ ...method, phase: 'POST', mechanism: '@PostAuthorize' })).toBe('@PostAuthorize · after');
    expect(checkHead({ ...method, scope: 'FIELD', field: 'ssn' })).toBe('ssn · @PreAuthorize');
    expect(checkHead({ ...method, fieldOwner: 'x.graphql.Employee', field: 'salary' })).toBe('Employee.salary');
  });
});
