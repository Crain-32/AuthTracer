import { beforeEach, describe, expect, it } from 'vitest';

import { app, endpoint, ingress, model } from '@/test/graphs';

import { useUi } from './store';

const ui = () => useUi.getState();

beforeEach(() => useUi.setState(useUi.getInitialState(), true));

describe('the app state', () => {
  it('starts on the request paths, loading, with nothing selected', () => {
    expect(ui()).toMatchObject({ model: null, diff: null, view: 'paths', selection: null,
      status: { text: 'Loading…', busy: true } });
  });

  it('starts every view afresh when a graph loads, and says where it came from', () => {
    ui().setPaths({ search: 'owners', open: new Set(['a']) });
    ui().setLineage({ endpoint: 'a|ingress:GET /x', field: 'name' });
    ui().setExposures({ filter: 'ssn' });
    ui().select({ type: 'node', qid: 'a/ingress:GET /x' });
    const loaded = model([app('a', [ingress('/x')])]);
    ui().loadModel(loaded);
    expect(ui().model).toBe(loaded);
    expect(ui().selection).toBeNull();
    expect(ui().paths).toEqual({ service: '', follow: true, open: new Set(), search: '' });
    expect(ui().lineage).toEqual({ endpoint: null, field: '', expanded: new Set() });
    expect(ui().exposures).toEqual({ filter: '', expanded: new Set() });
    expect(ui().status).toEqual({ text: 'test' });
  });

  it('shows a diff report when one loads, keeping the graph', () => {
    const loaded = model([app('a', [])]);
    ui().loadModel(loaded);
    ui().select({ type: 'node', qid: 'a/x' });
    const report = { base: 'main', head: 'feature', changes: [] };
    ui().loadDiff(report, 'diff.json');
    expect(ui()).toMatchObject({ view: 'diff', selection: null, model: loaded, diff: { report, name: 'diff.json' } });
  });

  it('closes the details when another view opens, not when the same one does', () => {
    const selection = { type: 'node' as const, qid: 'a/x' };
    ui().select(selection);
    ui().show('paths');
    expect(ui().selection).toBe(selection);
    ui().show('findings');
    expect(ui()).toMatchObject({ view: 'findings', selection: null });
  });

  it('keeps the details open when an exposure\'s lineage opens, on that endpoint and field', () => {
    const exposure = endpoint('a', '/x', 'ROLE_A', 'name');
    ui().select({ type: 'exposure', exposure });
    ui().setLineage({ expanded: new Set(['box']) });
    ui().showLineage('a', 'ingress:GET /x', 'name');
    expect(ui()).toMatchObject({ view: 'lineage', selection: { type: 'exposure', exposure } });
    expect(ui().lineage).toEqual({ endpoint: 'a|ingress:GET /x', field: 'name', expanded: new Set(['box']) });
    ui().showLineage('a', 'ingress:GET /y');
    expect(ui().lineage.field).toBe('');
  });

  it('changes one view\'s state a part at a time', () => {
    ui().setPaths({ search: 'x' });
    ui().setPaths({ follow: false });
    expect(ui().paths).toMatchObject({ search: 'x', follow: false, service: '' });
    ui().setExposures({ expanded: new Set(['k']) });
    expect(ui().exposures).toEqual({ filter: '', expanded: new Set(['k']) });
    ui().setStatus({ text: 'Failed', error: true });
    expect(ui().status).toEqual({ text: 'Failed', error: true });
  });
});
