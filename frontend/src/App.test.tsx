import { act, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { useUi } from '@/lib/store';
import type { ApplicationGraph, SystemGraph } from '@/lib/types';
import { app, endpoint, ingress } from '@/test/graphs';
import { renderUi } from '@/test/render';
import { json, later, stubServer, type Answer } from '@/test/server';
import { linkedSystem } from '@/test/system';

import { App } from './App';

let routes: Record<string, Answer>;
let server: ReturnType<typeof stubServer>;

const { system, exposures } = linkedSystem();
const snapshots = [{ id: 1, kind: 'APPLICATION', service: 'profile-service', createdAt: 't' },
  { id: 2, kind: 'APPLICATION', service: 'employee-service', createdAt: 't' }];

beforeEach(() => {
  routes = {
    'GET /api/graphs': json(snapshots),
    'GET /api/system': json(system),
    'GET /api/system/exposures': json(exposures),
    'GET /api/graphs/profile-service': json(system.services[0]),
    'GET /api/graphs/employee-service': json(system.services[1]),
    'POST /api/exposures': json(exposures),
  };
  server = stubServer(routes);
});

afterEach(() => vi.restoreAllMocks());

const file = (name: string, content: unknown) => new File([JSON.stringify(content)], name, { type: 'application/json' });
const origin = () => useUi.getState().model?.origin;
/** The headline number shown before a label. */
const number = (label: string) => screen.getAllByText(label).map(found => found.previousElementSibling)
  .find(found => found?.classList.contains('tabular-nums'))!;
const stat = (label: string) => number(label).textContent;
const nav = (title: string) => screen.getByRole('link', { name: new RegExp(`^${title}`) });
const page = () => screen.getByRole('navigation').parentElement!;
const fileInput = () => document.querySelector('input[type=file]') as HTMLInputElement;

async function renderApp() {
  const rendered = renderUi(<App />);
  await waitFor(() => expect(server).toHaveBeenCalledWith('/api/system', undefined));
  return rendered;
}

describe('App', () => {
  it('loads the newest system graph at the start, with its headline numbers', async () => {
    const slow = later();
    routes['GET /api/system'] = slow.answer;
    await renderApp();
    expect(screen.getByText('Loading the latest system graph…')).toBeInTheDocument();
    await act(async () => slow.send(new Response(JSON.stringify(system))));
    expect(await screen.findByRole('heading', { name: 'Request paths' })).toBeInTheDocument();
    expect(screen.queryByText('Loading the latest system graph…')).not.toBeInTheDocument();
    expect(screen.getByText('Latest stored system graph')).toBeInTheDocument();
    expect([stat('Services'), stat('Endpoints'), stat('No Authorization'), stat('Links'), stat('Findings')])
      .toEqual(['2', '4', '2', '1', '4']);
    expect(number('No Authorization')).toHaveClass('text-deny');
    expect(number('Findings')).toHaveClass('text-request');
    expect(nav('Findings')).toHaveTextContent('Findings4');
    expect(nav('Request paths')).toHaveClass('text-primary');
    expect(location.hash).toBe('#paths');
  });

  it('names the services and the observed links on hover', async () => {
    const { user } = await renderApp();
    await screen.findByRole('heading', { name: 'Request paths' });
    await user.hover(screen.getByText('Services'));
    expect(await screen.findByRole('tooltip')).toHaveTextContent('profile-service@test employee-service@test');
  });

  it('says when no system graph is stored yet, and still shows the views that need none', async () => {
    routes['GET /api/system'] = () => new Response('', { status: 404 });
    const { user } = await renderApp();
    expect(await screen.findByText('No system graph stored yet: publish graphs and link them, or open a file.'))
      .not.toHaveClass('text-deny');
    expect(screen.getByRole('heading', { name: 'No graph loaded yet' })).toBeInTheDocument();
    await user.click(nav('Legend'));
    expect(screen.getByRole('heading', { name: 'Legend' })).toBeInTheDocument();
    await user.click(nav('Diff report'));
    expect(screen.getByRole('heading', { name: 'No diff report loaded' })).toBeInTheDocument();
  });

  it('shows a load that fails as an error', async () => {
    routes['GET /api/system'] = json({ detail: 'The graph store is unreachable' }, 500);
    await renderApp();
    expect((await screen.findByText('GET /api/system: 500 The graph store is unreachable')).parentElement)
      .toHaveClass('text-deny');
  });

  it('loads a stored service\'s graph on request, its numbers plain when nothing is open and nothing found', async () => {
    routes['POST /api/exposures'] = json([endpoint('employee-service', '/employees/{id}', 'authenticated')]);
    const { user } = await renderApp();
    const select = screen.getByRole('combobox', { name: 'Stored service graph' });
    await waitFor(() => expect(select).toHaveTextContent('Stored service graph…'));
    await user.click(select);
    await user.click(await screen.findByRole('option', { name: 'employee-service' }));
    await waitFor(() => expect(origin()).toBe('Stored graph of employee-service'));
    expect(server).toHaveBeenCalledWith('/api/exposures', expect.objectContaining({ method: 'POST' }));
    expect([stat('Services'), stat('Endpoints'), stat('No Authorization'), stat('Findings')]).toEqual(['1', '1', '0', '0']);
    expect(number('No Authorization')).not.toHaveClass('text-deny');
    expect(number('Findings')).not.toHaveClass('text-request');
    expect(nav('Findings')).toHaveTextContent(/^Findings$/);
  });

  it('says when no service graph is stored, or the server is unavailable', async () => {
    routes['GET /api/graphs'] = json([]);
    const { unmount } = await renderApp();
    await waitFor(() => expect(screen.getByRole('combobox', { name: 'Stored service graph' }))
      .toHaveTextContent('No stored service graphs'));
    unmount();
    routes['GET /api/graphs'] = () => { throw new TypeError('Failed to fetch'); };
    await renderApp();
    expect(screen.getByRole('combobox', { name: 'Stored service graph' })).toHaveTextContent('Server unavailable');
  });

  it('shows a stored service graph that fails to load as an error', async () => {
    routes['GET /api/graphs/profile-service'] = json({ message: 'Corrupt snapshot' }, 500);
    const { user } = await renderApp();
    await screen.findByRole('heading', { name: 'Request paths' });
    await user.click(screen.getByRole('combobox', { name: 'Stored service graph' }));
    await user.click(await screen.findByRole('option', { name: 'profile-service' }));
    expect(await screen.findByText('GET /api/graphs/profile-service: 500 Corrupt snapshot')).toBeInTheDocument();
    expect(origin()).toBe('Latest stored system graph');
  });

  it('links the stored graphs, then loads what the link wrote', async () => {
    const link = later();
    routes['POST /api/system/link'] = link.answer;
    const { user } = await renderApp();
    await screen.findByRole('heading', { name: 'Request paths' });
    await user.click(screen.getByRole('button', { name: 'Link stored graphs' }));
    expect(screen.getByText('Linking the stored graphs with the trace store…')).toBeInTheDocument();
    await act(async () => link.send(new Response('{}')));
    await waitFor(() => expect(server.mock.calls.filter(([url]) => url === '/api/system')).toHaveLength(2));
    await waitFor(() => expect(screen.queryByText(/Loading|Linking/)).not.toBeInTheDocument());
  });

  it('says when there is nothing stored to link, and shows other link failures as they are', async () => {
    routes['POST /api/system/link'] = json({ detail: 'No graphs' }, 422);
    const { user } = await renderApp();
    await screen.findByRole('heading', { name: 'Request paths' });
    await user.click(screen.getByRole('button', { name: 'Link stored graphs' }));
    expect(await screen.findByText('No graphs stored yet: publish them with scan --publish http://localhost:8080'))
      .toBeInTheDocument();
    routes['POST /api/system/link'] = json({ detail: 'Zipkin is down' }, 502);
    await user.click(screen.getByRole('button', { name: 'Link stored graphs' }));
    expect(await screen.findByText('POST /api/system/link: 502 Zipkin is down')).toBeInTheDocument();
  });

  it('loads the newest system graph again on request', async () => {
    const { user } = await renderApp();
    await screen.findByRole('heading', { name: 'Request paths' });
    await user.click(screen.getByRole('button', { name: 'Latest system graph' }));
    await waitFor(() => expect(server.mock.calls.filter(([url]) => url === '/api/system')).toHaveLength(2));
  });

  it('opens the files the person picks: graphs, diff reports, and says which it can\'t read', async () => {
    const pick = vi.spyOn(HTMLInputElement.prototype, 'click');
    const { user } = await renderApp();
    await screen.findByRole('heading', { name: 'Request paths' });
    await user.click(screen.getByRole('button', { name: 'Open file' }));
    expect(pick).toHaveBeenCalled();
    await user.upload(fileInput(), file('profile-service.json', system.services[0]));
    await waitFor(() => expect(origin()).toBe('File profile-service.json'));
    expect(fileInput().value).toBe('');
    await user.upload(fileInput(), [file('notes.json', { name: 'notes' }),
      file('diff.json', { base: 'main', head: 'feature', changes: [] })]);
    expect(await screen.findByText('Diff report diff.json loaded')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Diff report' })).toBeInTheDocument();
    expect(origin()).toBe('File profile-service.json');
  });

  it('says which file it can\'t read', async () => {
    const { user } = await renderApp();
    await screen.findByRole('heading', { name: 'Request paths' });
    await user.upload(fileInput(), file('notes.json', { name: 'notes' }));
    expect(await screen.findByText('notes.json: notes.json is not an application graph, a system graph or a diff report'))
      .toBeInTheDocument();
  });

  it('opens files dropped on the page, showing where to drop them while they are dragged over it', async () => {
    await renderApp();
    await screen.findByRole('heading', { name: 'Request paths' });
    fireEvent.dragOver(page(), { dataTransfer: { types: ['text/plain'], files: [] } });
    expect(screen.queryByText('Drop graph or diff files')).not.toBeInTheDocument();
    fireEvent.dragOver(page(), { dataTransfer: { types: ['Files'], files: [] } });
    expect(screen.getByText('Drop graph or diff files')).toBeInTheDocument();
    // Moving over the page's own parts keeps it; leaving the page hides it.
    fireEvent(page(), new MouseEvent('dragleave', { bubbles: true, relatedTarget: screen.getByRole('main') }));
    expect(screen.getByText('Drop graph or diff files')).toBeInTheDocument();
    fireEvent(page(), new MouseEvent('dragleave', { bubbles: true, relatedTarget: null }));
    expect(screen.queryByText('Drop graph or diff files')).not.toBeInTheDocument();
    fireEvent.dragOver(page(), { dataTransfer: { types: ['Files'], files: [] } });
    fireEvent.drop(page(), { dataTransfer: { types: ['Files'], files: [file('diff.json', { base: 'a', head: 'b',
      changes: [] })] } });
    expect(screen.queryByText('Drop graph or diff files')).not.toBeInTheDocument();
    expect(await screen.findByRole('heading', { name: 'Diff report' })).toBeInTheDocument();
    fireEvent.drop(page(), { dataTransfer: { types: [], files: [] } });
    expect(screen.getByRole('heading', { name: 'Diff report' })).toBeInTheDocument();
  });

  it('switches views from the sidebar and the address, and Back returns to the view before', async () => {
    const { user } = await renderApp();
    await screen.findByRole('heading', { name: 'Request paths' });
    await user.click(nav('Exposures'));
    expect(screen.getByRole('heading', { name: 'Exposures' })).toBeInTheDocument();
    expect(location.hash).toBe('#exposures');
    act(() => { location.hash = '#identities'; });
    expect(await screen.findByRole('heading', { name: 'Identities' })).toBeInTheDocument();
    act(() => { location.hash = '#nonsense'; });
    await waitFor(() => expect(location.hash).toBe('#nonsense'));
    expect(screen.getByRole('heading', { name: 'Identities' })).toBeInTheDocument();
    act(() => history.back());
    await waitFor(() => expect(location.hash).toBe('#identities'));
    act(() => history.back());
    expect(await screen.findByRole('heading', { name: 'Exposures' })).toBeInTheDocument();
  });

  it('gives a view opened from code its own history entry, so Back returns', async () => {
    const replace = vi.spyOn(history, 'replaceState');
    const push = vi.spyOn(history, 'pushState');
    const { user } = await renderApp();
    await screen.findByRole('heading', { name: 'Request paths' });
    // The first view replaces the address that named none.
    expect(replace).toHaveBeenCalledWith(null, '', '#paths');
    await user.upload(fileInput(), file('diff.json', { base: 'main', head: 'feature', changes: [] }));
    expect(await screen.findByRole('heading', { name: 'Diff report' })).toBeInTheDocument();
    expect(push).toHaveBeenCalledWith(null, '', '#diff');
    act(() => history.back());
    expect(await screen.findByRole('heading', { name: 'Request paths' })).toBeInTheDocument();
  });

  it('opens on the view the address names', async () => {
    history.replaceState(null, '', '/#findings');
    await renderApp();
    expect(await screen.findByRole('heading', { name: 'Findings' })).toBeInTheDocument();
    expect(location.hash).toBe('#findings');
  });

  it('shows the details of what was clicked beside the view, and closes them when another view opens', async () => {
    const { user } = await renderApp();
    await screen.findByRole('heading', { name: 'Request paths' });
    await user.click(nav('Exposures'));
    await user.click(screen.getByRole('button', { name: 'ssn' }));
    const details = screen.getByRole('complementary');
    expect(within(details).getByRole('heading', { name: 'ssn' })).toBeInTheDocument();
    await user.click(within(details).getByRole('button', { name: 'Show its lineage' }));
    expect(await screen.findByRole('heading', { name: 'Field lineage' })).toBeInTheDocument();
    expect(location.hash).toBe('#lineage');
    expect(screen.getByRole('complementary')).toBeInTheDocument();
    await user.click(nav('Findings'));
    expect(screen.queryByRole('complementary')).not.toBeInTheDocument();
  });

  it('shows a view that breaks on a graph it doesn\'t understand in place, and the next view again', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const broken: ApplicationGraph = app('a', [ingress('/x'), { ...ingress('/y'), route: undefined } as never]);
    const odd: SystemGraph = { ...system, services: [broken], links: [], observations: [] };
    routes['GET /api/system'] = json(odd);
    routes['GET /api/system/exposures'] = json([endpoint('a', '/x', 'none')]);
    const { user } = await renderApp();
    expect(await screen.findByRole('heading', { name: 'This part of the graph couldn\'t be shown' })).toBeInTheDocument();
    expect(screen.getByText(/localeCompare/)).toBeInTheDocument();
    await user.click(nav('Exposures'));
    expect(screen.getByRole('heading', { name: 'Exposures' })).toBeInTheDocument();
  });

  it('keeps a graph the person opened over the newest system graph still on its way', async () => {
    const slow = later();
    routes['GET /api/system'] = slow.answer;
    const { user } = await renderApp();
    await user.upload(fileInput(), file('profile-service.json', system.services[0]));
    await waitFor(() => expect(origin()).toBe('File profile-service.json'));
    await act(async () => slow.send(new Response(JSON.stringify(system))));
    expect(origin()).toBe('File profile-service.json');
  });

  it('keeps a graph the person opened while the stored graphs were being linked', async () => {
    const link = later();
    routes['POST /api/system/link'] = link.answer;
    const { user } = await renderApp();
    await screen.findByRole('heading', { name: 'Request paths' });
    await user.click(screen.getByRole('button', { name: 'Link stored graphs' }));
    await user.upload(fileInput(), file('profile-service.json', system.services[0]));
    await waitFor(() => expect(origin()).toBe('File profile-service.json'));
    await act(async () => link.send(new Response('{}')));
    expect(server.mock.calls.filter(([url]) => url === '/api/system')).toHaveLength(1);
    expect(origin()).toBe('File profile-service.json');
    expect(useUi.getState().status).toEqual({ text: 'File profile-service.json' });
  });

  it('keeps quiet about a link that fails after the person opened a graph', async () => {
    const link = later();
    routes['POST /api/system/link'] = link.answer;
    const { user } = await renderApp();
    await screen.findByRole('heading', { name: 'Request paths' });
    await user.click(screen.getByRole('button', { name: 'Link stored graphs' }));
    await user.upload(fileInput(), file('profile-service.json', system.services[0]));
    await waitFor(() => expect(origin()).toBe('File profile-service.json'));
    await act(async () => link.send(new Response('{"detail":"No graphs"}', { status: 422 })));
    expect(useUi.getState().status).toEqual({ text: 'File profile-service.json' });
  });

  it('ignores a slower load that fails after a newer one', async () => {
    const slow = later();
    routes['GET /api/system'] = slow.answer;
    const { user } = await renderApp();
    await user.upload(fileInput(), file('profile-service.json', system.services[0]));
    await waitFor(() => expect(origin()).toBe('File profile-service.json'));
    await act(async () => slow.send(new Response('', { status: 500 })));
    expect(useUi.getState().status).toEqual({ text: 'File profile-service.json' });
  });

  it('keeps the service graph asked for last when an earlier one arrives later, or fails', async () => {
    const slowA = later();
    routes['GET /api/graphs/profile-service'] = slowA.answer;
    const { user } = await renderApp();
    await screen.findByRole('heading', { name: 'Request paths' });
    const select = screen.getByRole('combobox', { name: 'Stored service graph' });
    await user.click(select);
    await user.click(await screen.findByRole('option', { name: 'profile-service' }));
    expect(screen.getByText('Loading profile-service…')).toBeInTheDocument();
    await user.click(select);
    await user.click(await screen.findByRole('option', { name: 'employee-service' }));
    await waitFor(() => expect(origin()).toBe('Stored graph of employee-service'));
    await act(async () => slowA.send(new Response(JSON.stringify(system.services[0]))));
    expect(origin()).toBe('Stored graph of employee-service');

    const failing = later();
    routes['GET /api/graphs/profile-service'] = failing.answer;
    await user.click(select);
    await user.click(await screen.findByRole('option', { name: 'profile-service' }));
    await user.click(screen.getByRole('button', { name: 'Latest system graph' }));
    await waitFor(() => expect(origin()).toBe('Latest stored system graph'));
    await act(async () => failing.send(new Response('', { status: 500 })));
    expect(useUi.getState().status).toEqual({ text: 'Latest stored system graph' });
  });

  it('switches the theme from the sidebar', async () => {
    const { user } = await renderApp();
    await user.click(within(screen.getByRole('navigation')).getByRole('button', { name: 'Toggle theme' }));
    expect(document.documentElement).toHaveClass('dark');
  });
});
