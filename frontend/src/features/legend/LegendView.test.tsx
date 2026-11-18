import { screen, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { CHANGE_KINDS, FINDING_KINDS, kindTitle } from '@/lib/format';
import { renderUi } from '@/test/render';

import { LegendView } from './LegendView';

const section = (title: string) => within(screen.getByRole('heading', { name: title }).closest('.rounded-xl') as HTMLElement);

describe('LegendView', () => {
  it('explains every part of the views, drawn as they draw it, none of it reacting to a click', () => {
    renderUi(<LegendView />);
    expect(screen.getAllByRole('heading', { level: 3 }).map(heading => heading.textContent)).toEqual(['Request paths',
      'Field lineage', 'Tables', 'Finding kinds', 'Diff change kinds']);
    expect(screen.queryAllByRole('button')).toEqual([]);
  });

  it('draws each step of a request path, with the badges it can carry', () => {
    renderUi(<LegendView />);
    const paths = section('Request paths');
    expect(paths.getByText('Request · Rule /profiles/**')).toBeInTheDocument();
    expect(paths.getByText('Field · ssn · @PreAuthorize')).toBeInTheDocument();
    expect(paths.getByText('12 granted')).toBeInTheDocument();
    for (const label of ['masks', 'nulls', 'filters', 'token relay', 'OAuth2', 'fixed creds', 'no creds', 'creds?']) {
      expect(paths.getByText(`"${label}"`, { exact: false })).toBeInTheDocument();
    }
    expect(paths.getByText('Denies when denied')).toBeInTheDocument();
  });

  it('draws the lineage\'s classes: a response, a guarded source, a folded pass-through', () => {
    renderUi(<LegendView />);
    const lineage = section('Field lineage');
    expect(lineage.getByText('profile-service · response')).toBeInTheDocument();
    expect(lineage.getByText('json contact.email')).toBeInTheDocument();
    expect(lineage.getByText('check ROLE_ADMIN')).toBeInTheDocument();
    expect(lineage.getByText('7 fields, unchanged')).toBeInTheDocument();
    expect(['Direct', 'Complex', 'Computed'].map(name => lineage.getAllByText(name).length)).toEqual([1, 1, 1]);
  });

  it('names every finding and change kind the server reports', () => {
    renderUi(<LegendView />);
    expect(section('Finding kinds').getAllByRole('term').map(term => term.textContent))
      .toEqual(Object.keys(FINDING_KINDS).map(kindTitle));
    expect(section('Diff change kinds').getAllByRole('term').map(term => term.textContent))
      .toEqual(Object.keys(CHANGE_KINDS).map(kindTitle));
    expect(section('Tables').getByText('Diff row: REVIEW')).toBeInTheDocument();
  });
});
