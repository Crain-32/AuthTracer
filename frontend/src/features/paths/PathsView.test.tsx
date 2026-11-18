import { fireEvent, screen, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { Model } from '@/lib/model';
import { useUi } from '@/lib/store';
import { app, check, egress, endpoint, ingress, link, model, system } from '@/test/graphs';
import { renderUi } from '@/test/render';
import { linkedModel } from '@/test/system';

import { PathsView } from './PathsView';

const card = (name: RegExp) => screen.getByRole('button', { name, expanded: false });
const diagram = () => within(screen.getByTestId('rf__wrapper'));

describe('PathsView', () => {
  it('puts endpoints whose paths end the same way in one card, with what each needs', () => {
    renderUi(<PathsView model={linkedModel()} />);
    expect(screen.getByText('4 endpoints in 2 cards')).toBeInTheDocument();
    const profiles = card(/GET\/profiles\/\{id\}/);
    expect(profiles).toHaveTextContent('profile-serviceGET/profiles/{id}SCOPE_profiles.read and ROLE_USER3 checks');
    expect(profiles).toHaveTextContent('employee-serviceGET/employees/{id}authenticated1 check · called by profile-service');
    expect(card(/\/actuator\/health/)).toHaveTextContent('No Authorization0 checks');
  });

  it('opens a card on its diagram, a lane per service, each step showing its details', async () => {
    const { user } = renderUi(<PathsView model={linkedModel()} />);
    const profiles = card(/\/profiles\/\{id\}/);
    await user.click(profiles);
    expect(profiles).toHaveAttribute('aria-expanded', 'true');
    const rule = await diagram().findByRole('button', { name: /Request · Rule \/profiles\/\*\*/, pressed: false });
    expect(diagram().getByText('profile-service')).toBeInTheDocument();
    expect(diagram().getByText('employee-service')).toBeInTheDocument();
    expect(diagram().getByRole('button', { name: /Method · @PreAuthorize/ })).toHaveTextContent('4 granted · 1 denied');
    expect(diagram().getByRole('button', { name: /Field · ssn · @PreAuthorize/ })).toHaveTextContent('masks');
    expect(diagram().getByRole('button', { name: /RestClient/ })).toHaveTextContent('token relay');
    await user.click(rule);
    expect(useUi.getState().selection).toEqual({ type: 'node', qid: 'profile-service/location:rule' });
    expect(rule).toHaveAttribute('aria-pressed', 'true');
    await user.click(profiles);
    expect(screen.queryByTestId('rf__wrapper')).not.toBeInTheDocument();
  });

  it('shows a local step\'s or a call\'s details from its arrow', async () => {
    const { user } = renderUi(<PathsView model={linkedModel()} />);
    await user.click(card(/\/profiles\/\{id\}/));
    const call = await diagram().findByLabelText('Network-observed link');
    expect(within(call).getByText('5 calls')).toBeInTheDocument();
    fireEvent.click(call);
    expect(useUi.getState().selection).toMatchObject({ type: 'link', link: { from: 'profile-service/egress:employees' } });
    fireEvent.click(diagram().getAllByLabelText('Local call path')[0]);
    expect(useUi.getState().selection).toMatchObject({ type: 'edge', service: 'profile-service',
      edge: { from: 'ingress:GET /profiles/{id}', to: 'location:rule', order: 1 } });
  });

  it('marks a step that runs on some branches only, and names the methods between steps', async () => {
    const graph = app('a', [ingress('/x'), check('location:1'), check('location:2')],
      { 'ingress:GET /x': ['location:1', 'location:2'] });
    graph.edges[1] = { ...graph.edges[1], conditional: true, via: ['x.Service#a()', 'x.Service#b(long)'] };
    const { user } = renderUi(<PathsView model={model([graph])} />);
    await user.click(card(/GET\/x/));
    const branch = await diagram().findByLabelText('Local call path: on some branches only, via Service#a → Service#b');
    expect(branch.querySelector('.react-flow__edge-path')).toHaveStyle({ strokeDasharray: '5 4' });
    expect(diagram().getByLabelText('Local call path').querySelector('.react-flow__edge-path'))
      .not.toHaveStyle({ strokeDasharray: '5 4' });
  });

  it('labels a call by what the traces saw of it: how often, that they saw it, or only inferred', async () => {
    const caller = app('a', [ingress('/one'), ingress('/two'), egress('egress:seen', '/x'), egress('egress:guessed', '/y')],
      { 'ingress:GET /one': ['egress:seen'], 'ingress:GET /two': ['egress:guessed'] });
    const callee = app('b', [ingress('/x'), ingress('/y'), check('location:x'), check('location:y')],
      { 'ingress:GET /x': ['location:x'], 'ingress:GET /y': ['location:y'] });
    const m = model([caller, callee], [link('a/egress:seen', 'b/ingress:GET /x', 'NETWORK_OBSERVED'),
      { ...link('a/egress:guessed', 'b/ingress:GET /y'), bidirectional: false }]);
    const { user } = renderUi(<PathsView model={m} />);
    await user.click(screen.getByRole('button', { name: 'Expand all' }));
    const [seen, guessed] = await Promise.all([screen.findByLabelText('Network-observed link'),
      screen.findByLabelText('Network-inferred link')]);
    expect(seen).toHaveTextContent('observed');
    expect(seen.querySelector('.react-flow__edge-path')).toHaveAttribute('marker-start');
    expect(guessed).toHaveTextContent('inferred');
    expect(guessed.querySelector('.react-flow__edge-path')).toHaveStyle({ strokeDasharray: '6 4' });
    expect(guessed.querySelector('.react-flow__edge-path')).not.toHaveAttribute('marker-start');
  });

  it('says a filter check records no trace, and a check the traces never saw was not seen', async () => {
    const filter = { ...check('location:filter'), mechanism: '@PostFilter', denial: { kind: 'FILTER' as const } };
    const graph = app('a', [ingress('/x'), check('location:seen'), check('location:unseen'), filter],
      { 'ingress:GET /x': ['location:seen', 'location:unseen', 'location:filter'] });
    const traced = system([graph]);
    traced.observations = [{ subject: 'a/location:seen', kind: 'LOCATION', count: 2, granted: 2, denied: 0 }];
    const { user } = renderUi(<PathsView model={new Model(traced, [], 'test')} />);
    await user.click(card(/GET\/x/));
    expect(await diagram().findByRole('button', { name: /@PostFilter/ })).toHaveTextContent('filters record no trace');
    expect(diagram().getAllByText('not seen in traces')).toHaveLength(1);
    expect(diagram().getByText('2 granted')).toBeInTheDocument();
  });

  it('sums up alike endpoints of a card several services share, with who calls them', async () => {
    const service = (name: string) => app(name, ['/x/1', '/x/2', '/x/3', '/x/4'].map(route => ingress(route)));
    const calls = ['/x/1', '/x/2', '/x/3', '/x/4'].flatMap(route => ['a', 'b'].map(name =>
      link(`gateway/egress:${route}`, `${name}/ingress:GET ${route}`)));
    const { user } = renderUi(<PathsView model={model([service('a'), service('b'), app('gateway', [])], calls)} />);
    const line = screen.getByText(/4 endpoints under/);
    expect(line.closest('button')).toHaveTextContent('a, b4 endpoints under /x0 checks · called by gateway');
    await user.hover(screen.getByText('a, b'));
    expect(await screen.findByRole('tooltip')).toHaveTextContent('a b');
  });

  it('lists the endpoints of a card with nothing on their paths, each showing its details', async () => {
    const { user } = renderUi(<PathsView model={linkedModel()} />);
    await user.click(card(/\/actuator\/health/));
    const list = screen.getByRole('list');
    await user.click(within(list).getByRole('button', { name: 'GET/actuator/info' }));
    expect(useUi.getState().selection).toEqual({ type: 'node', qid: 'profile-service/ingress:GET /actuator/info' });
    expect(screen.queryByTestId('rf__wrapper')).not.toBeInTheDocument();
  });

  it('opens and closes every card at once', async () => {
    const { user } = renderUi(<PathsView model={linkedModel()} />);
    await user.click(screen.getByRole('button', { name: 'Expand all' }));
    expect(screen.queryAllByRole('button', { expanded: false })).toHaveLength(1);
    await user.click(screen.getByRole('button', { name: 'Collapse all' }));
    expect(screen.queryAllByRole('button', { expanded: true })).toHaveLength(0);
  });

  it('filters the cards by every word of the search, and says when none match', async () => {
    const { user } = renderUi(<PathsView model={linkedModel()} />);
    const search = screen.getByRole('textbox', { name: 'Filter endpoints' });
    await user.type(search, 'Employees authenticated');
    expect(screen.getByText('4 endpoints in 2 cards; 1 match the filter')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /actuator/ })).not.toBeInTheDocument();
    // Expanding all opens only the cards that match.
    await user.click(screen.getByRole('button', { name: 'Expand all' }));
    await user.clear(search);
    expect(card(/actuator/)).toBeInTheDocument();
    await user.type(search, 'graphql');
    expect(screen.getByRole('heading', { name: 'No endpoints match' })).toBeInTheDocument();
    expect(screen.queryByText(/Calls outside requests/)).not.toBeInTheDocument();
  });

  it('shows one service\'s cards, then all of them again', async () => {
    const { user } = renderUi(<PathsView model={linkedModel()} />);
    await user.click(screen.getByRole('combobox', { name: 'Service' }));
    await user.click(await screen.findByRole('option', { name: 'employee-service' }));
    expect(screen.getByText('1 endpoint in 1 card')).toBeInTheDocument();
    expect(useUi.getState().paths.service).toBe('employee-service');
    await user.click(screen.getByRole('combobox', { name: 'Service' }));
    await user.click(await screen.findByRole('option', { name: 'All services' }));
    expect(screen.getByText('4 endpoints in 2 cards')).toBeInTheDocument();
  });

  it('counts only a service\'s own checks when calls are not followed', async () => {
    const { user } = renderUi(<PathsView model={linkedModel()} />);
    await user.click(screen.getByRole('switch', { name: 'Follow calls into services' }));
    expect(screen.getByText('4 endpoints in 3 cards')).toBeInTheDocument();
    expect(card(/\/profiles\/\{id\}/)).toHaveTextContent('2 checks');
  });

  it('sums up more than three alike endpoints in one line, listing them on hover', async () => {
    const graph = app('a', ['/x/1', '/x/2', '/x/3', '/x/4', '/y'].map(route => ingress(route)));
    const { user } = renderUi(<PathsView model={model([graph])} />);
    const line = screen.getByText(/4 endpoints/);
    expect(line).toHaveTextContent('4 endpoints under /x');
    await user.hover(line);
    expect(await screen.findByRole('tooltip')).toHaveTextContent('GET /x/1 GET /x/2 GET /x/3 GET /x/4');
    expect(card(/GET\/y/)).toBeInTheDocument();
  });

  it('draws a card that reads the same in several services once, naming them', async () => {
    const health = (service: string) => app(service, [ingress('/actuator/health'), check('location:health', [])],
      { 'ingress:GET /actuator/health': ['location:health'] });
    const { user } = renderUi(<PathsView model={model(['a', 'b', 'c', 'd'].map(health))} />);
    expect(screen.getByText('4 endpoints in 1 card')).toBeInTheDocument();
    const tag = screen.getByText('4 services');
    await user.hover(tag);
    expect(await screen.findByRole('tooltip')).toHaveTextContent('a b c d');
    await user.click(card(/actuator\/health/));
    expect(screen.getByText('Drawn for a; the same in b, c, d.')).toBeInTheDocument();
  });

  it('names two or three services a card stands for in full', () => {
    const health = (service: string) => app(service, [ingress('/actuator/health')]);
    renderUi(<PathsView model={model([health('a'), health('b')], [], [endpoint('a', '/actuator/health', 'none'),
      endpoint('b', '/actuator/health', 'none')])} />);
    expect(screen.getAllByText('a, b')).toHaveLength(1);
  });

  it('says what an endpoint returns on hover', async () => {
    const { user } = renderUi(<PathsView model={linkedModel()} />);
    await user.hover(within(card(/\/profiles\/\{id\}/)).getByText('/profiles/{id}'));
    expect(await screen.findByRole('tooltip')).toHaveTextContent('Returns ProfileView');
  });

  it('names the calls made outside any request, with the services they reach', async () => {
    const graph = app('a', [ingress('/x'), egress('egress:jwks', '/oauth2/jwks'), egress('egress:config', '/config')]);
    const m = model([graph, app('auth', [ingress('/oauth2/jwks')])], [link('a/egress:jwks', 'auth/ingress:GET /oauth2/jwks')]);
    const { user } = renderUi(<PathsView model={m} />);
    const outside = screen.getByRole('button', { name: 'Calls outside requests (token checks, configuration, discovery): 2' });
    await user.click(outside);
    expect(outside).toHaveAttribute('aria-expanded', 'true');
    const jwks = screen.getByRole('button', { name: /GET\/oauth2\/jwks→ auth/ });
    expect(screen.getByRole('button', { name: /GET\/config→ no scanned service/ })).toBeInTheDocument();
    await user.click(jwks);
    expect(useUi.getState().selection).toEqual({ type: 'node', qid: 'a/egress:jwks' });
  });
});
