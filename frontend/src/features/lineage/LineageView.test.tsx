import { fireEvent, screen, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import type { Model } from '@/lib/model';
import { useUi } from '@/lib/store';
import type { Exposure, Flow } from '@/lib/types';
import { app, endpoint, field, link, model } from '@/test/graphs';
import { renderUi } from '@/test/render';
import { linkedModel } from '@/test/system';

import { LineageView } from './LineageView';

const diagram = () => within(screen.getByTestId('rf__wrapper'));
const box = async (title: string) => (await diagram().findByText(title, { selector: 'span' }))
  .closest('.react-flow__node') as HTMLElement;

/** Renders the view and waits for its diagram, which draws once its container has a width. */
async function renderLineage(m: Model) {
  const rendered = renderUi(<LineageView model={m} />);
  await screen.findByTestId('rf__wrapper');
  return rendered;
}

const flow = (from: string, to: string, source: Flow['source'] = 'DIRECT', kind: Flow['kind'] = 'LOCAL',
  path = 'a/ingress:GET /p'): Flow => ({ path, from, to, source, kind });

/** GET /p's fields id and name copied unchanged from Source through Dto into View, and label computed from both. */
function chain(): Exposure[] {
  const field = (name: string, lineage: Flow[]): Exposure => ({ ...endpoint('a', '/p', 'ROLE_A', name),
    fieldId: `a/field:x.View.${name}`, lineage });
  return [endpoint('a', '/p', 'ROLE_A'),
    field('id', [flow('a/field:x.Dto.id', 'a/field:x.View.id'), flow('a/field:x.Source.id', 'a/field:x.Dto.id')]),
    field('name', [flow('a/field:x.Dto.name', 'a/field:x.View.name'), flow('a/field:x.Source.name', 'a/field:x.Dto.name')]),
    field('label', [flow('a/field:x.Source.id', 'a/field:x.View.label', 'COMPUTED'),
      flow('a/field:x.Source.name', 'a/field:x.View.label', 'COMPUTED')]),
    endpoint('a', '/q', 'ROLE_A')];
}

describe('LineageView', () => {
  it('opens on the endpoint with the most behind its fields, drawing where each comes from', async () => {
    const { user } = await renderLineage(linkedModel());
    expect(screen.getByRole('combobox', { name: 'Endpoint' })).toHaveTextContent('profile-service GET /profiles/{id}');
    expect(screen.getByRole('combobox', { name: 'Field' })).toHaveTextContent('All response fields (2)');
    const source = await box('Employee');
    expect(source).toHaveTextContent('employee-service · source');
    expect(within(source).getByRole('button', { name: 'ssnPII' })).toBeInTheDocument();
    expect(source).toHaveTextContent('check ROLE_ADMINmasks');
    expect(await box('ProfileView')).toHaveTextContent('profile-service · response');
    expect(diagram().getByLabelText('2 fields copied as is')).toBeInTheDocument();
    await user.hover(screen.getByText('2 fields as is'));
    expect(await screen.findByRole('tooltip')).toHaveTextContent('name, ssn');
    // The table below the diagram: the endpoint, then its fields.
    expect(screen.getByRole('heading', { name: 'What a caller needs, per field' })).toBeInTheDocument();
    expect(screen.getAllByRole('row')).toHaveLength(4);
  });

  it('shows one field\'s lineage, and another endpoint\'s fields', async () => {
    const { user } = await renderLineage(linkedModel());
    await user.click(screen.getByRole('combobox', { name: 'Field' }));
    await user.click(await screen.findByRole('option', { name: 'ssn' }));
    expect(useUi.getState().lineage.field).toBe('ssn');
    const source = await box('Employee');
    expect(within(source).queryByRole('button', { name: 'name' })).not.toBeInTheDocument();
    expect(screen.getAllByRole('row')).toHaveLength(3);
    await user.click(screen.getByRole('combobox', { name: 'Endpoint' }));
    await user.click(await screen.findByRole('option', { name: 'employee-service GET /employees/{id}' }));
    expect(useUi.getState().lineage).toMatchObject({ endpoint: 'employee-service|ingress:GET /employees/{id}', field: '' });
    expect(screen.getByRole('heading', { name: 'No response fields' })).toBeInTheDocument();
    expect(screen.getByRole('combobox', { name: 'Field' })).toHaveTextContent('All response fields (0)');
  });

  it('keeps the endpoint and field it was opened on', () => {
    useUi.getState().showLineage('profile-service', 'ingress:GET /profiles/{id}', 'name');
    renderUi(<LineageView model={linkedModel()} />);
    expect(screen.getByRole('combobox', { name: 'Field' })).toHaveTextContent('name');
  });

  it('says when the graph has no endpoints', () => {
    renderUi(<LineageView model={model([app('a', [])])} />);
    expect(screen.getByRole('heading', { name: 'No endpoints' })).toBeInTheDocument();
  });

  it('folds a class every field passes through unchanged into one line, and opens it on a click', async () => {
    const { user } = await renderLineage(model([app('a', [])], [], chain()));
    const dto = await box('Dto');
    const head = within(dto).getByRole('button', { expanded: false });
    expect(dto).toHaveTextContent('2 fields, unchanged');
    await user.hover(head);
    expect(await screen.findByRole('tooltip')).toHaveTextContent('x.Dto 2 fields, copied in and out unchanged: click to show'
      + ' them');
    await user.click(head);
    expect(head).toHaveAttribute('aria-expanded', 'true');
    expect(within(dto).getByRole('button', { name: 'id' })).toBeInTheDocument();
    await user.click(head);
    expect(head).toHaveAttribute('aria-expanded', 'false');
    // Classes with something to show on their rows can't fold.
    expect(within(await box('View')).queryByRole('button', { expanded: true })).not.toBeInTheDocument();
  });

  it('shows a field\'s details from its row, and a flow\'s from its arrow', async () => {
    const { user } = await renderLineage(model([app('a', [])], [], chain()));
    await user.click(within(await box('Source')).getByRole('button', { name: 'name' }));
    expect(useUi.getState().selection).toEqual({ type: 'node', qid: 'a/field:x.Source.name' });
    // Two computed inputs of one field: two arrows, one label.
    const computed = diagram().getAllByLabelText(/^Computed: /);
    expect(computed).toHaveLength(2);
    expect(diagram().getAllByText('computed')).toHaveLength(1);
    fireEvent.click(computed[0]);
    expect(useUi.getState().selection).toMatchObject({ type: 'flow', flow: { to: 'a/field:x.View.label' } });
    // A shared arrow stands for several flows, so it has no details of its own: the flow's stay.
    fireEvent.click((await diagram().findAllByLabelText('2 fields copied as is'))[0]);
    expect(useUi.getState().selection).toMatchObject({ type: 'flow', flow: { to: 'a/field:x.View.label' } });
  });

  it('draws a value from another service thick, dashed until a trace has seen the call', async () => {
    const field = (name: string, egress: string, to = name): Exposure => ({ ...endpoint('a', '/p', 'ROLE_A', to),
      fieldId: `a/field:x.View.${to}`, lineage: [flow(`b/field:x.Employee.${name}`, `a/field:x.View.${to}`, 'DIRECT',
        'NETWORK', egress)] });
    const exposures = [endpoint('a', '/p', 'ROLE_A'), field('ssn', 'a/egress:guess'), field('name', 'a/egress:guess'),
      field('id', 'a/egress:seen', 'key'), field('phone', 'a/egress:unlinked', 'tel')];
    await renderLineage(model([app('a', []), app('b', [])], [link('a/egress:guess', 'b/ingress:GET /x'),
      link('a/egress:seen', 'b/ingress:GET /y', 'NETWORK_OBSERVED')], exposures));
    const shared = await diagram().findByLabelText('2 fields copied as is');
    expect(shared.querySelector('.react-flow__edge-path')).toHaveStyle({ strokeDasharray: '7 5', strokeWidth: '4' });
    const direct = 'Direct: the same value, possibly renamed or reassigned, across a ';
    const seen = diagram().getByLabelText(`${direct}network-observed link`);
    expect(seen.querySelector('.react-flow__edge-path')).toHaveStyle({ strokeWidth: '3.5' });
    expect(seen.querySelector('.react-flow__edge-path')).not.toHaveStyle({ strokeDasharray: '7 5' });
    expect(diagram().getByLabelText(`${direct}network-inferred link`).querySelector('.react-flow__edge-path'))
      .toHaveStyle({ strokeDasharray: '7 5' });
  });

  it('draws a field fed by another of its own class with an arrow inside the class', async () => {
    const exposures = [endpoint('a', '/p', 'ROLE_A'), { ...endpoint('a', '/p', 'ROLE_A', 'full'),
      fieldId: 'a/field:x.View.full', lineage: [flow('a/field:x.View.first', 'a/field:x.View.full', 'COMPUTED'),
        flow('a/field:x.Source.first', 'a/field:x.View.first')] }];
    await renderLineage(model([app('a', [])], [], exposures));
    const [inside] = (await diagram().findAllByLabelText(/^Computed: /));
    expect(inside).toHaveClass('react-flow__edge-smoothstep');
    expect(diagram().getByLabelText(/^Direct: /)).toHaveClass('react-flow__edge-default');
  });

  it('marks a declassified field apart from its labels', async () => {
    const exposures = [endpoint('a', '/p', 'ROLE_A'), { ...endpoint('a', '/p', 'ROLE_A', 'salary'),
      fieldId: 'a/field:x.View.salary', lineage: [flow('a/field:x.Employee.salary', 'a/field:x.View.salary')] }];
    await renderLineage(model([app('a', [field('x.Employee', 'salary', { labels: ['PAY'], declassified: true })])], [],
      exposures));
    expect(within(await box('Employee')).getByText('declassified')).toHaveClass('text-muted-foreground');
    expect(within(await box('Employee')).getByText('PAY')).toHaveClass('text-deny');
  });
});
