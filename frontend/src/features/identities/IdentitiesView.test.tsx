import { screen, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { Model } from '@/lib/model';
import type { IdentityUsage } from '@/lib/types';
import { app, model, system } from '@/test/graphs';
import { renderUi } from '@/test/render';

import { IdentitiesView } from './IdentitiesView';

const identity = (more: Partial<IdentityUsage>): IdentityUsage => ({ authorities: [], authenticationType: 'Jwt',
  requests: 1, endpoints: ['GET /x'], needed: [], unneeded: [], denied: 0, unread: 0, ...more });

function withIdentities(identities: IdentityUsage[]): Model {
  const linked = system([app('a', [])]);
  linked.identities = identities;
  return new Model(linked, [], 'test');
}

describe('IdentitiesView', () => {
  it('says where identities come from when the traces had none', () => {
    renderUi(<IdentitiesView model={model([app('a', [])])} />);
    expect(screen.getByRole('heading', { name: 'No identities' })).toBeInTheDocument();
    expect(screen.getByText(/link the graphs with Zipkin/)).toBeInTheDocument();
  });

  it('shows what each identity was granted, which of it its requests needed, and what was denied', async () => {
    const { user } = renderUi(<IdentitiesView model={withIdentities([
      identity({ authorities: ['ROLE_ADMIN', 'ROLE_USER'], requests: 12, endpoints: ['GET /a', 'GET /b'],
        needed: ['ROLE_USER'], unneeded: ['ROLE_ADMIN'], denied: 3, unread: 2 }),
      identity({ authorities: [], unread: 1 }),
    ])} />);
    expect(screen.getAllByRole('columnheader').map(header => header.textContent)).toEqual(['Requests', 'Needed',
      'Not needed', 'Denied']);
    const [overScoped, anonymous] = screen.getAllByRole('row').slice(1).map(row => within(row).getAllByRole('cell'));
    expect(overScoped.map(cell => cell.textContent)).toEqual(['12 on 2 endpoints', 'ROLE_USER',
      'ROLE_ADMIN2 checks AuthTracer can\'t read might need these', '3']);
    expect(anonymous.map(cell => cell.textContent)).toEqual(['1 on 1 endpoint', '—',
      '—1 check AuthTracer can\'t read might need these', '—']);
    await user.hover(screen.getByText('12 on 2 endpoints'));
    expect(await screen.findByRole('tooltip')).toHaveTextContent('GET /a GET /b');
  });

  it('names the authentication type when the identities have more than one', () => {
    renderUi(<IdentitiesView model={withIdentities([identity({ authenticationType: 'JwtAuthenticationToken' }),
      identity({ authenticationType: 'UsernamePasswordAuthenticationToken' })])} />);
    expect(screen.getAllByRole('columnheader')[0]).toHaveTextContent('Type');
    expect(screen.getByRole('cell', { name: 'UsernamePasswordAuthenticationToken' })).toBeInTheDocument();
  });
});
