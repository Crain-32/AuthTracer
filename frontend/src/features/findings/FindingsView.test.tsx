import { screen, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { app, model } from '@/test/graphs';
import { renderUi } from '@/test/render';
import { linkedModel } from '@/test/system';

import { FindingsView } from './FindingsView';

const section = (title: RegExp) => screen.getByRole('heading', { name: title }).closest('.rounded-xl') as HTMLElement;

describe('FindingsView', () => {
  it('says when there is nothing to look at', () => {
    renderUi(<FindingsView model={model([app('a', [])])} />);
    expect(screen.getByRole('heading', { name: 'No findings' })).toBeInTheDocument();
  });

  it('lists the kinds that most often leave an endpoint open first, each with what it means and how many', () => {
    renderUi(<FindingsView model={linkedModel()} />);
    expect(screen.getAllByRole('heading', { level: 3 }).map(heading => heading.textContent)).toEqual([
      'Open sensitive endpoint 1', 'Bypassed 2', 'Unmatched call 1']);
    expect(section(/Bypassed/)).toHaveTextContent('Enforced in general, but skipped on this call path');
  });

  it('shows a finding with short names, its full text and code on hover', async () => {
    const { user } = renderUi(<FindingsView model={linkedModel()} />);
    const open = within(section(/Open sensitive endpoint/));
    expect(open.getByRole('row')).toHaveTextContent('profile-serviceActuator heapdump (GET /actuator/heapdump) answers anyone'
      + 'org.springframework.boot.actuate.management.HeapDumpWebEndpoint');
    const linker = within(section(/Unmatched call/)).getByRole('row');
    expect(linker).toHaveTextContent('system (linker)A traced call GET /legacy matches no ingress');
    await user.hover(open.getByText('org.springframework.boot.actuate.management.HeapDumpWebEndpoint'));
    expect(await screen.findByRole('tooltip')).toHaveTextContent('org.springframework.boot.actuate.management.HeapDumpWebEndpoint');
  });

  it('merges findings that differ in a word into one, a line per finding saying what fills the blank', async () => {
    const { user } = renderUi(<FindingsView model={linkedModel()} />);
    const bypassed = within(section(/Bypassed/));
    expect(bypassed.getAllByRole('row')).toHaveLength(1);
    expect(bypassed.getByText('…').closest('p')).toHaveTextContent('…is called on this, skipping its check');
    const lines = bypassed.getAllByRole('listitem');
    expect(lines.map(line => line.textContent)).toEqual(['ProfileService#audit(long)ProfileService#find:33',
      'ProfileService#export(long)ProfileService#list:52']);
    await user.hover(within(lines[1]).getByText('ProfileService#export(long)'));
    expect(await screen.findByRole('tooltip')).toHaveTextContent('dev.crain.profileservice.ProfileService#export(long) is called on'
      + ' this, skipping its check');
  });

  it('shows the blanks of a message where they are, and what fills each', () => {
    const graph = app('a', []);
    graph.findings = ['shutdown', 'loggers'].map(name => ({ kind: 'OPEN_SENSITIVE_ENDPOINT',
      message: `Actuator ${name} (POST /actuator/${name}) answers anyone: it stops the application` }));
    renderUi(<FindingsView model={model([graph])} />);
    const merged = within(section(/Open sensitive endpoint/));
    expect(merged.getByText(/answers anyone/).closest('p')).toHaveTextContent('Actuator …(POST …answers anyone: it stops the'
      + ' application');
    expect(merged.getAllByRole('listitem').map(line => line.textContent)).toEqual(['shutdown · /actuator/shutdown)',
      'loggers · /actuator/loggers)']);
  });

  it('shows a kind this UI has no words for yet after the ones it knows', () => {
    const graph = app('a', []);
    graph.findings = [{ kind: 'SOMETHING_NEWER', message: 'from a newer scanner' }, { kind: 'PROVIDED_CONFLICT',
      message: 'lost to an Org fact' }];
    renderUi(<FindingsView model={model([graph])} />);
    expect(screen.getAllByRole('heading', { level: 3 }).map(heading => heading.textContent)).toEqual([
      'Provided conflict 1', 'Something newer 1']);
  });

  it('lists the Provided facts each scan applied', () => {
    const graph = app('a', []);
    graph.provided = [
      { kind: 'LABEL', subject: 'x.Employee.ssn', labels: ['PII', 'HR'], origin: 'ORG' },
      { kind: 'REQUIREMENT', subject: 'GET /internal/**', requirement: 'ROLE_INTERNAL', reason: 'behind the VPN',
        origin: 'LOCAL' },
      { kind: 'CHECK', subject: 'x.Guard#allowed(long)', origin: 'ORG_OVERRIDE' },
    ];
    renderUi(<FindingsView model={model([graph])} />);
    const facts = within(section(/Provided facts applied/));
    expect(screen.getByRole('heading', { name: 'Provided facts applied 3' })).toBeInTheDocument();
    expect(facts.getAllByRole('row').map(row => row.textContent)).toEqual([
      'ServiceKindSubjectLabels / requirementReasonOrigin',
      'aLABELx.Employee.ssnPII, HRORG',
      'aREQUIREMENTGET /internal/**ROLE_INTERNALbehind the VPNLOCAL',
      'aCHECKx.Guard#allowed(long)ORG_OVERRIDE',
    ]);
    expect(screen.getByRole('heading', { name: 'No findings' })).toBeInTheDocument();
  });
});
