import { screen, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { useUi } from '@/lib/store';
import type { Exposure } from '@/lib/types';
import { app, endpoint, model } from '@/test/graphs';
import { renderUi } from '@/test/render';
import { linkedModel } from '@/test/system';

import { ExposuresView } from './ExposuresView';

const rowOf = (name: string | RegExp) => screen.getByRole('button', { name }).closest('tr')!;
const fields = (route: string, names: string[], more: Partial<Exposure> = {}): Exposure[] =>
  names.map(name => ({ ...endpoint('a', route, 'ROLE_A', name), ...more }));

describe('ExposuresView', () => {
  it('lists each endpoint, then what each of its fields asks beyond it and where it comes from', () => {
    renderUi(<ExposuresView model={linkedModel()} />);
    expect(screen.getByText('6 of 6 exposures')).toBeInTheDocument();
    expect(screen.getAllByRole('columnheader').map(header => header.textContent)).toEqual(['Endpoint / field', 'Requires',
      'Comes from', 'Labels']);
    expect(rowOf('profile-serviceGET/profiles/{id}')).toHaveTextContent('SCOPE_profiles.read and ROLE_USER');
    expect(rowOf('name')).toHaveTextContent('namenothing moreemployee-service Employee.name');
    expect(rowOf('ssn')).toHaveTextContent('ssn+ ROLE_ADMINemployee-service Employee.ssnPII');
    expect(within(rowOf('profile-serviceGET/actuator/health')).getByText('none')).toBeInTheDocument();
  });

  it('filters by every word, a matching field bringing its endpoint along, and says when nothing matches', async () => {
    const { user } = renderUi(<ExposuresView model={linkedModel()} />);
    const filter = screen.getByRole('searchbox', { name: 'Filter exposures' });
    await user.type(filter, 'PII admin');
    expect(screen.getByText('1 of 6 exposures')).toBeInTheDocument();
    expect(screen.getAllByRole('row').slice(1).map(row => within(row).getAllByRole('button')[0].textContent))
      .toEqual(['profile-serviceGET/profiles/{id}', 'ssn']);
    await user.clear(filter);
    await user.type(filter, 'graphql');
    expect(screen.getByText('0 of 6 exposures')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Nothing matches' })).toBeInTheDocument();
    expect(screen.queryByRole('table')).not.toBeInTheDocument();
  });

  it('shows a row\'s details on a click, and marks it', async () => {
    const { user } = renderUi(<ExposuresView model={linkedModel()} />);
    await user.click(screen.getByRole('button', { name: 'ssn' }));
    expect(screen.getByRole('button', { name: 'ssn' })).toHaveAttribute('aria-pressed', 'true');
    expect(useUi.getState().selection).toMatchObject({ type: 'exposure', exposure: { field: 'ssn' } });
    await user.click(rowOf('profile-serviceGET/actuator/info'));
    expect(screen.getByRole('button', { name: 'ssn' })).toHaveAttribute('aria-pressed', 'false');
    expect(screen.getByRole('button', { name: 'profile-serviceGET/actuator/info' })).toHaveAttribute('aria-pressed', 'true');
  });

  it('sums up more than three alike endpoints in one row, listing them on hover and on a click', async () => {
    const exposures = ['health', 'info', 'metrics', 'prometheus'].map(name => endpoint('gateway', `/actuator/${name}`,
      'none'));
    const { user } = renderUi(<ExposuresView model={model([app('gateway', [])], [], exposures)} />);
    const summary = screen.getByRole('button', { name: 'gateway4 endpoints under /actuator', expanded: false });
    expect(summary.closest('tr')).toHaveTextContent('noneno response fields');
    expect(screen.queryByRole('columnheader', { name: 'Labels' })).not.toBeInTheDocument();
    await user.hover(summary);
    expect(await screen.findByRole('tooltip')).toHaveTextContent('GET /actuator/health GET /actuator/info');
    await user.click(summary);
    expect(summary).toHaveAttribute('aria-expanded', 'true');
    expect(screen.getByRole('button', { name: 'gatewayGET/actuator/prometheus' })).toBeInTheDocument();
    await user.click(summary);
    expect(screen.queryByRole('button', { name: 'gatewayGET/actuator/prometheus' })).not.toBeInTheDocument();
  });

  it('folds the fields that ask nothing beyond their endpoint into one row, and opens it on a click', async () => {
    const exposures = [endpoint('a', '/owners', 'ROLE_A'), ...fields('/owners', ['id', 'name', 'city', 'phone']),
      // The server couldn't tell what this one adds, but it asks the same.
      { ...endpoint('a', '/owners', 'ROLE_A', 'email'), adds: null }];
    const { user } = renderUi(<ExposuresView model={model([app('a', [])], [], exposures)} />);
    const folded = screen.getByRole('button', { name: '5 fields:city, email, id, name, phone', expanded: false });
    expect(folded.closest('tr')).toHaveTextContent('nothing more');
    await user.click(folded);
    expect(screen.queryByRole('button', { name: /5 fields/ })).not.toBeInTheDocument();
    expect(rowOf('phone')).toHaveTextContent('nothing more');
    expect(rowOf('email')).toHaveTextContent('nothing more');
  });

  it('keeps the labels column in line under summary and folded rows', () => {
    const exposures = [...['health', 'info', 'metrics', 'prometheus'].map(name => endpoint('a', `/actuator/${name}`,
      'none')), endpoint('a', '/owners', 'ROLE_A'), ...fields('/owners', ['id', 'name', 'city', 'phone']),
    endpoint('a', '/vets', 'ROLE_A'), { ...endpoint('a', '/vets', 'ROLE_A', 'license'), labels: ['PII'] }];
    renderUi(<ExposuresView model={model([app('a', [])], [], exposures)} />);
    const width = (row: HTMLElement) => within(row).getAllByRole('cell').length;
    const summary = screen.getByRole('button', { name: /4 endpoints/ }).closest('tr')!;
    const folded = screen.getByRole('button', { name: /4 fields/ }).closest('tr')!;
    expect([width(summary), width(folded), width(rowOf('license'))]).toEqual([4, 4, 4]);
  });

  it('shows what every field adds once, on its endpoint, and each field only what it adds beyond that', () => {
    const exposures = [endpoint('a', '/owners', 'ROLE_A'),
      { ...endpoint('a', '/owners', 'ROLE_A and @PostFilter', 'id'), adds: '@PostFilter' },
      { ...endpoint('a', '/owners', 'ROLE_A and @PostFilter and ROLE_HR', 'ssn'), adds: '@PostFilter and ROLE_HR' }];
    renderUi(<ExposuresView model={model([app('a', [])], [], exposures)} />);
    expect(rowOf('aGET/owners')).toHaveTextContent('every field: + @PostFilter');
    expect(rowOf('id')).toHaveTextContent('nothing more');
    expect(rowOf('ssn')).toHaveTextContent('+ ROLE_HR');
  });

  it('shows a field\'s whole requirement when the server can\'t tell what it adds', () => {
    const exposures = [endpoint('a', '/owners', 'ROLE_A'), { ...endpoint('a', '/owners', 'ROLE_B', 'id'), adds: null }];
    renderUi(<ExposuresView model={model([app('a', [])], [], exposures)} />);
    expect(rowOf('id')).toHaveTextContent('idROLE_B');
  });

  it('marks the policies a field breaks, on its labels and on its endpoint, with the policy on hover', async () => {
    const violation = { label: 'PII', requires: 'ROLE_HR', reason: 'salary data' };
    const exposures = [{ ...endpoint('a', '/owners', 'ROLE_A'), violations: [violation] },
      { ...endpoint('a', '/owners', 'ROLE_A', 'ssn'), labels: ['PII', 'FINANCE'], violations: [violation] }];
    const { user } = renderUi(<ExposuresView model={model([app('a', [])], [], exposures)} />);
    expect(rowOf('aGET/owners')).toHaveTextContent('policy ✗');
    const badge = within(rowOf('ssn')).getByText('PII policy ✗');
    expect(rowOf('ssn')).toHaveTextContent('FINANCE');
    await user.hover(badge);
    expect(await screen.findByRole('tooltip')).toHaveTextContent('The PII policy requires ROLE_HR (salary data)');
  });

  it('names a policy with no reason by what it requires alone', async () => {
    const exposures = [endpoint('a', '/owners', 'ROLE_A'), { ...endpoint('a', '/owners', 'ROLE_A', 'ssn'), labels: ['PII'],
      violations: [{ label: 'PII', requires: 'ROLE_HR' }] }];
    const { user } = renderUi(<ExposuresView model={model([app('a', [])], [], exposures)} />);
    await user.hover(screen.getByText('PII policy ✗'));
    expect(await screen.findByRole('tooltip')).toHaveTextContent(/^The PII policy requires ROLE_HR$/);
  });
});
