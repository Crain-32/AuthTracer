import { act, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { Model } from '@/lib/model';
import { useUi, type Selection } from '@/lib/store';
import type { DenialKind, Edge, GraphNode, LocationNode, Scope } from '@/lib/types';
import { app, endpoint, field, link, model, system } from '@/test/graphs';
import { renderUi } from '@/test/render';
import { linkedModel, linkedSystem } from '@/test/system';

import { DetailsPanel } from './DetailsPanel';

/** The panel as the app shows it: for whatever is selected. */
function Panel({ model: shown }: { model: Model }) {
  const selection = useUi(state => state.selection);
  return selection && <DetailsPanel model={shown} selection={selection} />;
}

function show(shown: Model, selection: Selection) {
  useUi.getState().select(selection);
  return renderUi(<Panel model={shown} />);
}

const kind = () => screen.getByRole('complementary').querySelector('.uppercase')!.textContent;
const title = () => screen.getByRole('heading', { level: 3 }).textContent;
const terms = () => screen.getAllByRole('term').map(term => term.textContent);
/** The value a row of the panel shows for a term. */
const value = (term: string) => screen.getAllByRole('term').find(found => found.textContent === term)!
  .nextElementSibling as HTMLElement;

const location = (more: Partial<LocationNode>): LocationNode => ({ type: 'location', id: 'location:x', mechanism: '@PreAuthorize',
  scope: 'METHOD', phase: 'PRE', target: { className: 'x.Service', method: 'find(long)' }, ...more });

describe('DetailsPanel', () => {
  it('shows an endpoint: its handler, response, requirement and steps', async () => {
    const { user } = show(linkedModel(), { type: 'node', qid: 'profile-service/ingress:GET /profiles/{id}' });
    expect(kind()).toBe('Ingress');
    expect(title()).toBe('GET /profiles/{id}');
    expect(terms()).toEqual(['Service', 'Handler', 'Response', 'Endpoint requires', 'Steps on its path']);
    expect(value('Handler')).toHaveTextContent('ProfileController#get:18');
    expect(value('Response')).toHaveTextContent(/^dev.crain.profileservice.ProfileView$/);
    expect(value('Endpoint requires')).toHaveTextContent('SCOPE_profiles.read and ROLE_USER');
    expect(value('Steps on its path')).toHaveTextContent('3');
    await user.hover(screen.getByText('ProfileController#get:18'));
    expect(await screen.findByRole('tooltip')).toHaveTextContent('dev.crain.profileservice.ProfileController#get(long), line 18');
  });

  it('names an endpoint\'s callers, each showing its own details', async () => {
    const { user } = show(linkedModel(), { type: 'node', qid: 'employee-service/ingress:GET /employees/{id}' });
    expect(value('Called by')).toHaveTextContent('profile-service RestClient GET /employees/{id} (observed)');
    await user.click(screen.getByRole('button', { name: 'profile-service RestClient GET /employees/{id}' }));
    expect(kind()).toBe('Egress');
    expect(value('Links')).toHaveTextContent('employee-service GET /employees/{id} (observed)');
  });

  it('shows a collection response as one', () => {
    const shown = model([app('a', [{ type: 'ingress', id: 'ingress:GET /owners', httpMethod: 'GET', route: '/owners',
      response: { type: 'x.Owner', many: true } }])]);
    show(shown, { type: 'node', qid: 'a/ingress:GET /owners' });
    expect(value('Response')).toHaveTextContent('x.Owner (a collection)');
    expect(value('Steps on its path')).toHaveTextContent('0');
    expect(terms()).not.toContain('Endpoint requires');
  });

  it('shows a method check: what it requires, how it runs, and what the traces saw', () => {
    show(linkedModel(), { type: 'node', qid: 'profile-service/location:profiles' });
    expect(kind()).toBe('method check');
    expect(title()).toBe('@PreAuthorize');
    expect(terms()).toEqual(['Service', 'Requirement', 'Scope', 'Phase', 'Code', 'Proxied', 'Observed', 'Authorities']);
    expect(value('Requirement')).toHaveTextContent('ROLE_USER');
    expect(value('Scope')).toHaveTextContent('Method check (method security on a bean, through its proxy)');
    expect(value('Phase')).toHaveTextContent('PRE: before the code runs');
    expect(value('Proxied')).toHaveTextContent('yes: applied through Spring\'s proxy, so calls on this skip it');
    expect(value('Observed')).toHaveTextContent('5 evaluations: 4 granted, 1 denied');
    expect(value('Authorities')).toHaveTextContent(/^JWT claims; snapshot: fixed when the token was issued/);
  });

  it('shows a request rule by its pattern, unseen when the traces had decisions but none for it', () => {
    show(linkedModel(), { type: 'node', qid: 'profile-service/location:rule' });
    expect(kind()).toBe('request check');
    expect(value('Route pattern')).toHaveTextContent('/profiles/**');
    expect(value('Proxied')).toHaveTextContent(/^no$/);
    expect(value('Observed')).toHaveTextContent('not seen in the traces');
  });

  it('shows a field check: the field it guards and what a denied caller gets', () => {
    show(linkedModel(), { type: 'node', qid: 'employee-service/location:ssn' });
    expect(kind()).toBe('field check');
    expect(value('Guards field')).toHaveTextContent('ssn');
    expect(value('When denied')).toHaveTextContent('A custom handler replaces the value, typically with a mask. The request'
      + ' succeeds (SsnMask)');
  });

  it('shows how a check is written, when it runs after the method, and that filters leave no trace', () => {
    const linked = system([app('a', [location({ requirement: { kind: 'EXPRESSION', expression: 'hasRole(\'A\')' },
      phase: 'POST', denial: { kind: 'FILTER' } })])]);
    linked.observations = [{ subject: 'a/location:other', kind: 'LOCATION', count: 1, granted: 1, denied: 0 }];
    show(new Model(linked, [], 'test'), { type: 'node', qid: 'a/location:x' });
    expect(value('Written as')).toHaveTextContent('hasRole(\'A\')');
    expect(value('Phase')).toHaveTextContent('POST: after the method returns, on its result');
    expect(value('When denied')).toHaveTextContent('Denied elements are removed from the collection');
    expect(value('Observed')).toHaveTextContent('never: Spring Security records no decision span for filters');
    expect(terms()).not.toContain('Authorities');
  });

  it('shows a check of a scope or denial newer than this UI by its name, and none observed without traces', () => {
    show(model([app('a', [location({ scope: 'MESSAGE' as Scope, denial: { kind: 'REDIRECT' as DenialKind } })])]),
      { type: 'node', qid: 'a/location:x' });
    expect(kind()).toBe('MESSAGE check');
    expect(value('Scope')).toHaveTextContent(/^MESSAGE$/);
    expect(value('When denied')).toHaveTextContent(/^REDIRECT$/);
    expect(value('Observed')).toHaveTextContent('no traces in this graph');
  });

  it('shows a call: its client, credentials, where it goes, and what it links to', () => {
    show(linkedModel(), { type: 'node', qid: 'profile-service/egress:employees' });
    expect(kind()).toBe('Egress');
    expect(title()).toBe('GET /employees/{id}');
    expect(terms()).toEqual(['Service', 'Client', 'Credentials', 'Base URL', 'Call site', 'Links']);
    expect(value('Credentials')).toHaveTextContent('Relays the caller\'s token');
    expect(value('Base URL')).toHaveTextContent('http://employee-service');
    expect(value('Call site')).toHaveTextContent('Employees#find:40');
  });

  it('shows a call that matches no service, configured by expression, with credentials from code', () => {
    show(model([app('a', [{ type: 'egress', id: 'egress:x', client: 'WebClient', httpMethod: 'POST', uriTemplate: '/audit',
      baseUrlExpression: '${audit.url}', credentials: 'STATIC', credentialsVia: 'AuditConfig#client',
      response: { type: 'x.Receipt', many: false } }, { type: 'egress', id: 'egress:y', client: 'Feign',
      httpMethod: 'GET', uriTemplate: '/y', credentials: 'KERBEROS' as 'NONE' }])]), { type: 'node', qid: 'a/egress:x' });
    expect(value('Credentials')).toHaveTextContent('Sends fixed credentials: the called service checks this service, not its'
      + ' callersfrom AuditConfig#client');
    expect(value('Configured as')).toHaveTextContent('${audit.url}');
    expect(value('Response')).toHaveTextContent('Receipt');
    expect(value('Links')).toHaveTextContent('none: no linked service matches this call');
    act(() => useUi.getState().select({ type: 'node', qid: 'a/egress:y' }));
    expect(value('Credentials')).toHaveTextContent(/^KERBEROS$/);
  });

  it('shows the client a service\'s own token is issued to, and the scopes it asks for', () => {
    show(model([app('a', [{ type: 'egress', id: 'egress:x', client: 'gRPC', httpMethod: 'GRPC',
      uriTemplate: 'employees.v1.EmployeeDirectory/GetEmployee', credentials: 'OAUTH2_CLIENT',
      registration: { id: 'payroll-service', clientId: 'payroll-service', grantType: 'client_credentials',
        scopes: ['employees.read'], tokenUri: 'http://localhost:9000/oauth2/token' } }, { type: 'egress',
      id: 'egress:y', client: 'RestClient', httpMethod: 'GET', uriTemplate: '/y', credentials: 'OAUTH2_CLIENT',
      registration: { id: 'batch', issuerUri: 'https://idp.example.com' } }])]), { type: 'node', qid: 'a/egress:x' });
    expect(value('Token')).toHaveTextContent('As client payroll-service (registration payroll-service), with the scopes'
      + ' employees.readfrom http://localhost:9000/oauth2/token');
    act(() => useUi.getState().select({ type: 'node', qid: 'a/egress:y' }));
    expect(value('Token')).toHaveTextContent('As client (not set) (registration batch), with no scopesfrom'
      + ' https://idp.example.com');
  });

  it('shows a message sent to a broker as carrying no caller, and a gRPC rule as never traced', () => {
    const linked = system([app('a', [{ type: 'egress', id: 'egress:kafka', client: 'KafkaTemplate', httpMethod: 'KAFKA',
      uriTemplate: 'orders' }, location({ id: 'location:grpc', mechanism: 'authorizeRequests (gRPC)' })])]);
    linked.observations = [{ subject: 'a/location:other', kind: 'LOCATION', count: 1, granted: 1, denied: 0 }];
    linked.services[0].nodes.push({ type: 'egress', id: 'egress:rest', client: 'RestClient', httpMethod: 'GET',
      uriTemplate: '/x' });
    show(new Model(linked, [], 'test'), { type: 'node', qid: 'a/egress:kafka' });
    expect(value('Credentials')).toHaveTextContent(/^Sends a message, which carries no caller/);
    expect(terms()).not.toContain('Base URL');
    // A request with nothing AuthTracer saw set: no credentials to show.
    act(() => useUi.getState().select({ type: 'node', qid: 'a/egress:rest' }));
    expect(terms()).not.toContain('Credentials');
    act(() => useUi.getState().select({ type: 'node', qid: 'a/location:grpc' }));
    expect(value('Observed')).toHaveTextContent('never: Spring gRPC records authentication, not its request rules');
  });

  it('shows a field: its names, labels, the checks that guard it, where it comes from and goes', async () => {
    const graph = app('a', [field('x.Source', 'name', { jsonName: 'fullName', javaType: 'java.lang.String',
      labels: ['PII', 'HR'], declassified: true }), field('x.Dto', 'name'),
    location({ id: 'location:mask', scope: 'FIELD', field: 'name', target: { className: 'x.Source', method: 'getName()' },
      requirement: { kind: 'ANY_AUTHORITY', authorities: ['ROLE_HR'] }, denial: { kind: 'NULL' } }),
    location({ id: 'location:throw', scope: 'FIELD', field: 'name', target: { className: 'x.Source', method: 'getName()' },
      requirement: { kind: 'AUTHENTICATED' } })]);
    graph.flows = ['ingress:GET /a', 'ingress:GET /b'].map(path => ({ path, from: 'field:x.Source.name', to: 'field:x.Dto.name',
      source: 'DIRECT' as const, kind: 'LOCAL' as const }));
    const linked = system([graph, app('b', [field('x.Employee', 'name')])]);
    linked.flows = [{ from: 'b/field:x.Employee.name', to: 'a/field:x.Source.name', source: 'COMPUTED', kind: 'NETWORK' }];
    const { user } = show(new Model(linked, [], 'test'), { type: 'node', qid: 'a/field:x.Source.name' });
    expect(kind()).toBe('Field');
    expect(title()).toBe('name');
    expect(value('Owner')).toHaveTextContent('x.Source');
    expect(value('JSON name')).toHaveTextContent('fullName');
    expect(value('Java type')).toHaveTextContent('java.lang.String');
    expect(value('Labels')).toHaveTextContent('PII, HR');
    expect(value('Declassified')).toHaveTextContent('yes: a Provided fact says it no longer inherits');
    expect(value('Guarded by')).toHaveTextContent('ROLE_HR (@PreAuthorize, nulls when denied)authenticated (@PreAuthorize,'
      + ' denies when denied)');
    expect(value('Comes from')).toHaveTextContent('computed network b Employee.name');
    // The same flow on two paths is one line.
    expect(value('Flows into')).toHaveTextContent(/^direct a Dto.name$/);
    await user.click(screen.getByRole('button', { name: 'a Dto.name' }));
    expect(title()).toBe('name');
    expect(terms()).toEqual(['Service', 'Owner', 'Comes from']);
  });

  it('shows an opaque step\'s reason and site', () => {
    show(model([app('a', [{ type: 'opaque', id: 'opaque:1', reason: 'Reflection (Method.invoke)',
      site: { className: 'x.Dispatcher', method: 'call()', line: 4 } }])]), { type: 'node', qid: 'a/opaque:1' });
    expect(kind()).toBe('Opaque call path');
    expect(title()).toBe('Reflection (Method.invoke)');
    expect(value('Site')).toHaveTextContent('Dispatcher#call:4');
  });

  it('says when a node is not in the graph, and shows a node newer than this UI as its JSON', () => {
    const shown = model([app('a', [{ type: 'widget', id: 'widget:1', size: 3 } as unknown as GraphNode])]);
    show(shown, { type: 'node', qid: 'a/gone' });
    expect(kind()).toBe('Unknown');
    expect(title()).toBe('a/gone');
    expect(value('Note')).toHaveTextContent('Not in this graph');
    expect(screen.queryByText('JSON')).not.toBeInTheDocument();
    act(() => useUi.getState().select({ type: 'node', qid: 'a/widget:1' }));
    expect(kind()).toBe('Node');
    expect(title()).toBe('widget:1');
    expect(screen.getByText('JSON')).toBeInTheDocument();
    expect(screen.getByText(/"size": 3/)).toBeInTheDocument();
  });

  it('shows a local step of a path: where it goes, on which branches, through which methods', () => {
    const edge: Edge = { from: 'location:1', to: 'location:2', kind: 'LOCAL', path: 'ingress:GET /x', order: 2,
      via: ['x.A#a()', 'x.B#b()'], bidirectional: false, conditional: true };
    show(model([app('a', [])]), { type: 'edge', service: 'a', edge });
    expect(kind()).toBe('Local call path');
    expect(title()).toBe('Step 2');
    expect(value('Path of')).toHaveTextContent('ingress:GET /x');
    expect(value('On')).toHaveTextContent('some branches only: it doesn\'t count for the endpoint on its own');
    expect(screen.getAllByRole('listitem').map(item => item.textContent)).toEqual(['x.A#a()', 'x.B#b()']);
    act(() => useUi.getState().select({ type: 'edge', service: 'a', edge: { ...edge, via: [], conditional: false } }));
    expect(value('On')).toHaveTextContent('every way through');
    expect(value('Via')).toHaveTextContent('directly');
  });

  it('shows a link between services: what saw it, how often, which way', async () => {
    const shown = linkedModel();
    const { user } = show(shown, { type: 'link', link: shown.links[0] });
    expect(kind()).toBe('Network link');
    expect(title()).toBe('observed');
    expect(value('Kind')).toHaveTextContent('Network-observed: a trace showed this call');
    expect(value('Seen')).toHaveTextContent('5 calls in the traces');
    expect(value('Direction')).toHaveTextContent('both ways: arguments out, response back');
    await user.click(screen.getByRole('button', { name: 'employee-service GET /employees/{id}' }));
    expect(kind()).toBe('Ingress');
  });

  it('counts a link the traces saw once as one call', () => {
    const { system: graph, exposures } = linkedSystem();
    graph.observations = graph.observations.map(observation => observation.kind === 'LINK'
      ? { ...observation, count: 1 } : observation);
    const shown = new Model(graph, exposures, 'Latest stored system graph');
    show(shown, { type: 'link', link: shown.links[0] });
    expect(value('Seen')).toHaveTextContent(/^1 call in the traces$/);
  });

  it('shows a link no trace has seen yet, to a node outside the graph by its id', () => {
    show(model([app('a', [])]), { type: 'link', link: { ...link('a/egress:x', 'b/ingress:GET /x'), bidirectional: false } });
    expect(title()).toBe('inferred');
    expect(value('Kind')).toHaveTextContent('Network-inferred: matched statically');
    expect(terms()).not.toContain('Seen');
    expect(value('To ingress')).toHaveTextContent('b/ingress:GET /x');
    expect(value('Direction')).toHaveTextContent('one way');
  });

  it('shows a field flow: its ends, what kind of value it carries, and its path', () => {
    show(model([app('a', [])]), { type: 'flow', flow: { path: 'a/ingress:GET /p', from: 'a/field:x.A.b',
      to: 'a/field:x.C.d', source: 'COMPUTED', kind: 'LOCAL' } });
    expect(kind()).toBe('local flow');
    expect(title()).toBe('computed');
    expect(value('Field source')).toHaveTextContent('Computed: a non-structural operation');
    expect(value('Part of')).toHaveTextContent('a/ingress:GET /p');
  });

  it('shows an exposure: what it requires, the checks on the way, its sources, and its lineage on a click', async () => {
    const shown = linkedModel();
    const ssn = shown.exposures.find(exposure => exposure.field === 'ssn')!;
    const { user } = show(shown, { type: 'exposure', exposure: ssn });
    expect(kind()).toBe('Exposure');
    expect(title()).toBe('ssn');
    expect(screen.getByText(/^profile-service ·/)).toHaveTextContent('profile-service · GET /profiles/{id}');
    expect(screen.getAllByRole('listitem').map(item => item.textContent)).toEqual([
      'authorizeHttpRequestsSCOPE_profiles.read', '@PreAuthorizeROLE_USER', 'employee-service · @PreAuthorizeROLE_ADMIN']);
    expect(value('Sources')).toHaveTextContent('employee-service Employee.ssn');
    expect(value('Labels')).toHaveTextContent('PII');
    await user.click(screen.getByRole('button', { name: 'Show its lineage' }));
    expect(useUi.getState()).toMatchObject({ view: 'lineage', selection: { type: 'exposure', exposure: ssn },
      lineage: { endpoint: 'profile-service|ingress:GET /profiles/{id}', field: 'ssn' } });
    await user.click(screen.getByRole('button', { name: 'employee-service · @PreAuthorize' }));
    expect(kind()).toBe('field check');
  });

  it('shows an endpoint\'s own exposure, with no checks and no lineage to open', () => {
    show(linkedModel(), { type: 'exposure', exposure: endpoint('profile-service', '/actuator/health', 'none') });
    expect(title()).toBe('Endpoint');
    expect(value('Checks, in order')).toHaveTextContent(/^none$/);
    expect(terms()).toEqual(['Requires', 'Checks, in order']);
    expect(screen.queryByRole('button', { name: 'Show its lineage' })).not.toBeInTheDocument();
  });

  it('closes', async () => {
    const { user } = show(linkedModel(), { type: 'node', qid: 'profile-service/location:rule' });
    await user.click(screen.getByRole('button', { name: 'Close details' }));
    expect(useUi.getState().selection).toBeNull();
    expect(screen.queryByRole('complementary')).not.toBeInTheDocument();
  });
});
