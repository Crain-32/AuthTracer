import { screen, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { useUi } from '@/lib/store';
import type { Change } from '@/lib/types';
import { renderUi } from '@/test/render';

import { DiffView } from './DiffView';

const change = (kind: string, severity: Change['severity'], more: Partial<Change>): Change =>
  ({ kind, severity, service: 'profile-service', endpoint: 'GET /profiles/{id}', ...more });

/** A report as the server writes it: by severity, then kind, service, endpoint and field. */
const changes: Change[] = [
  change('WEAKENED', 'FAIL', { endpoint: 'GET /owners', before: 'ROLE_ADMIN and SCOPE_x', after: 'SCOPE_x',
    message: 'fewer callers are kept out than before' }),
  change('WEAKENED', 'FAIL', { endpoint: 'GET /owners/{id}', before: 'ROLE_ADMIN and SCOPE_x', after: 'SCOPE_x',
    message: 'fewer callers are kept out than before' }),
  change('POLICY_VIOLATION', 'FAIL', { field: 'salary', before: 'ROLE_HR', after: 'ROLE_USER', labels: ['PII'],
    message: 'the PII policy requires ROLE_HR' }),
  change('POLICY_VIOLATION', 'FAIL', { field: 'ssn', before: 'ROLE_HR', after: 'ROLE_USER', labels: ['PII', 'HR'],
    message: 'the PII policy requires ROLE_HR (dev.crain.Payroll)' }),
  change('NEW_FINDING', 'REVIEW', { endpoint: 'dev.crain.profileservice.Audit#log(long)', after: 'BYPASSED',
    message: 'dev.crain.profileservice.Audit#log(long) is called on this' }),
  change('NEW_FINDING', 'REVIEW', { endpoint: undefined, after: 'OPAQUE_CONFIG', message: 'a RoleHierarchy built at runtime' }),
  change('STRENGTHENED', 'INFO', { before: 'SCOPE_x', after: 'SCOPE_x and ROLE_USER' }),
  change('REMOVED', 'INFO', { endpoint: 'GET /legacy', before: 'authenticated', after: null }),
];

const load = (list: Change[]) => useUi.getState().loadDiff({ base: 'main', head: 'feature', changes: list }, 'diff.json');
const rows = () => screen.getAllByRole('row').slice(1);

describe('DiffView', () => {
  it('says how to write a report when none is loaded', () => {
    renderUi(<DiffView />);
    expect(screen.getByRole('heading', { name: 'No diff report loaded' })).toBeInTheDocument();
    expect(screen.getByText(/--json build\/reports\/authtracer\/diff.json/)).toBeInTheDocument();
  });

  it('fails when a change fails, with the count of each severity', () => {
    load(changes);
    renderUi(<DiffView />);
    expect(screen.getByText('Fails').nextElementSibling).toHaveTextContent('diff.json: main → feature');
    expect(screen.getByText('4 fail')).toBeInTheDocument();
    expect(screen.getByText('2 review')).toBeInTheDocument();
    expect(screen.getByText('2 info')).toBeInTheDocument();
  });

  it('keeps the report\'s order, one row per distinct change, its places listed together', () => {
    load(changes);
    renderUi(<DiffView />);
    expect(screen.getAllByRole('columnheader').map(header => header.textContent)).toEqual(['Severity', 'Change',
      'What changed', 'Where', 'Labels', 'Why']);
    expect(rows().map(row => within(row).getAllByRole('cell').slice(0, 3).map(cell => cell.textContent))).toEqual([
      ['FAIL', 'Weakened', '− ROLE_ADMIN'],
      ['FAIL', 'Policy violation', '− ROLE_HR+ ROLE_USER'],
      ['REVIEW', 'New finding', 'new: BYPASSED'],
      ['REVIEW', 'New finding', 'new: OPAQUE_CONFIG'],
      ['INFO', 'Strengthened', '+ ROLE_USER'],
      ['INFO', 'Removed', 'was: authenticated'],
    ]);
  });

  it('lists where a change applies, an endpoint\'s fields after it, with the labels they carry', () => {
    load(changes);
    renderUi(<DiffView />);
    const [weakened, violation, finding, linker] = rows().map(row => within(row).getAllByRole('cell'));
    expect(weakened[3]).toHaveTextContent('profile-serviceGET /ownersprofile-serviceGET /owners/{id}');
    expect(violation[3]).toHaveTextContent('profile-serviceGET /profiles/{id}·salaryssn');
    expect(violation[4]).toHaveTextContent('PIIHR');
    expect(finding[3]).toHaveTextContent('profile-serviceAudit#log(long)');
    expect(linker[3]).toHaveTextContent(/^profile-service$/);
  });

  it('says why: the one reason all places share, or what the kind means when they differ', async () => {
    load(changes);
    const { user } = renderUi(<DiffView />);
    const [weakened, violation] = rows().map(row => within(row).getAllByRole('cell'));
    expect(weakened[5]).toHaveTextContent('fewer callers are kept out than before');
    expect(violation[5]).toHaveTextContent('A field with a governed label (e.g. PII) is now exposed with less than its policy'
      + ' requires.');
    await user.hover(within(violation[5]).getByText(/governed label/));
    expect(await screen.findByRole('tooltip')).toHaveTextContent('the PII policy requires ROLE_HR the PII policy requires'
      + ' ROLE_HR (dev.crain.Payroll)');
  });

  it('shows a place\'s own change on hover', async () => {
    load(changes);
    const { user } = renderUi(<DiffView />);
    await user.hover(screen.getByText('ssn'));
    expect(await screen.findByRole('tooltip')).toHaveTextContent('the PII policy requires ROLE_HR (Payroll) ROLE_HR → ROLE_USER');
  });

  it('shows a place\'s change on its endpoint when it has no fields, with none for a missing side', async () => {
    load(changes);
    const { user } = renderUi(<DiffView />);
    await user.hover(screen.getByText('GET /legacy'));
    expect(await screen.findByRole('tooltip')).toHaveTextContent('authenticated → (none)');
  });

  it('needs review when nothing fails but something needs a look, and passes otherwise', () => {
    load(changes.filter(found => found.severity === 'REVIEW'));
    const { unmount } = renderUi(<DiffView />);
    expect(screen.getByText('Needs review')).toBeInTheDocument();
    expect(screen.queryByRole('columnheader', { name: 'Labels' })).not.toBeInTheDocument();
    unmount();
    load(changes.filter(found => found.severity === 'INFO'));
    renderUi(<DiffView />);
    expect(screen.getByText('Passes')).toBeInTheDocument();
  });

  it('passes with no changes at all, and says so', () => {
    load([]);
    renderUi(<DiffView />);
    expect(screen.getByText('Passes')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'No authorization changes' })).toBeInTheDocument();
  });
});
