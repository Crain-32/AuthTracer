import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { app, endpoint, ingress, system } from '@/test/graphs';
import { json, stubServer, type Answer } from '@/test/server';

import { linkStored, loadService, loadSystem, openFile, RequestError, storedServices } from './api';

let routes: Record<string, Answer>;
let fetchStub: ReturnType<typeof stubServer>;

beforeEach(() => {
  routes = {};
  fetchStub = stubServer(routes);
});

afterEach(() => vi.unstubAllGlobals());

describe('requests', () => {
  it('fail with the problem\'s detail, message or error, and the status', async () => {
    routes['GET /api/system'] = json({ detail: 'No system graph stored', message: 'm' }, 404);
    const error = await loadSystem().catch(caught => caught);
    expect(error).toBeInstanceOf(RequestError);
    expect(error).toMatchObject({ status: 404, message: 'GET /api/system: 404 No system graph stored' });
    routes['GET /api/system'] = json({ message: 'Boom' }, 500);
    await expect(loadSystem()).rejects.toThrow('GET /api/system: 500 Boom');
    routes['GET /api/system'] = json({ error: 'Bad Gateway' }, 502);
    await expect(loadSystem()).rejects.toThrow('GET /api/system: 502 Bad Gateway');
    routes['GET /api/system'] = json({ status: 503 }, 503);
    await expect(loadSystem()).rejects.toThrow('GET /api/system: 503 {"status":503}');
  });

  it('fail with the body as it is when it is no JSON object, clipped to a line', async () => {
    routes['POST /api/system/link'] = () => new Response('x'.repeat(400), { status: 500 });
    const error: Error = await linkStored().catch(caught => caught);
    expect(error.message).toBe(`POST /api/system/link: 500 ${'x'.repeat(299)}…`);
    routes['POST /api/system/link'] = () => new Response('null', { status: 500 });
    await expect(linkStored()).rejects.toThrow('POST /api/system/link: 500 null');
  });
});

describe('loading', () => {
  it('reads the newest system graph with its exposures', async () => {
    const graph = system([app('a', [ingress('/x')])]);
    routes['GET /api/system'] = json(graph);
    routes['GET /api/system/exposures'] = json([endpoint('a', '/x', 'none')]);
    const model = await loadSystem();
    expect(model.origin).toBe('Latest stored system graph');
    expect(model.services).toEqual(['a']);
    expect(model.endpointExposure('a/ingress:GET /x')?.requirement).toBe('none');
  });

  it('reads one service\'s stored graph and has the server work out its exposures', async () => {
    const graph = app('a b', [ingress('/x')]);
    routes['GET /api/graphs/a%20b'] = json(graph);
    routes['POST /api/exposures'] = json([endpoint('a b', '/x', 'ROLE_A')]);
    const model = await loadService('a b');
    expect(model.origin).toBe('Stored graph of a b');
    expect(model.endpointExposure('a b/ingress:GET /x')?.requirement).toBe('ROLE_A');
    const [, options] = fetchStub.mock.calls.at(-1)!;
    expect(options).toMatchObject({ method: 'POST', headers: { 'Content-Type': 'application/json' } });
    expect(JSON.parse(options!.body as string)).toEqual(graph);
  });

  it('lists the services with a stored application graph, each once, by name', async () => {
    routes['GET /api/graphs'] = json([
      { id: 3, kind: 'APPLICATION', service: 'employee-service', createdAt: 't' },
      { id: 2, kind: 'SYSTEM', service: 'system', createdAt: 't' },
      { id: 1, kind: 'APPLICATION', service: 'profile-service', createdAt: 't' },
      { id: 0, kind: 'APPLICATION', service: 'employee-service', createdAt: 't' },
    ]);
    expect(await storedServices()).toEqual(['employee-service', 'profile-service']);
  });

  it('links the stored graphs', async () => {
    routes['POST /api/system/link'] = json({});
    await linkStored();
    expect(fetchStub).toHaveBeenCalledWith('/api/system/link', { method: 'POST' });
  });
});

describe('openFile', () => {
  it('opens a diff report as it is, without the server', async () => {
    const report = { base: 'main', head: 'pr', changes: [] };
    expect(await openFile(new File([JSON.stringify(report)], 'diff.json'))).toEqual({ kind: 'diff', report });
    expect(fetchStub).not.toHaveBeenCalled();
  });

  it('opens an application or system graph with the exposures the server works out', async () => {
    routes['POST /api/exposures'] = json([endpoint('a', '/x', 'none')]);
    const opened = await openFile(new File([JSON.stringify(app('a', [ingress('/x')]))], 'a.json'));
    expect(opened.kind).toBe('model');
    const model = opened.kind === 'model' ? opened.model : null;
    expect(model?.origin).toBe('File a.json');
    expect(model?.exposures).toHaveLength(1);
    const linked = await openFile(new File([JSON.stringify(system([app('a', []), app('b', [])]))], 'system.json'));
    expect(linked.kind === 'model' && linked.model.services).toEqual(['a', 'b']);
  });

  it('refuses a file that is none of them', async () => {
    await expect(openFile(new File(['{"name":"x"}'], 'package.json')))
      .rejects.toThrow('package.json is not an application graph, a system graph or a diff report');
    await expect(openFile(new File(['not json'], 'notes.txt'))).rejects.toThrow(SyntaxError);
  });
});
