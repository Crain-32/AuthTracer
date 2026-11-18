import { screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { renderUi } from '@/test/render';

import { Endpoint, MethodBadge, RequirementBadge, ViewHeader } from './common';

describe('common parts', () => {
  it('color HTTP methods like an API reference, and leave messaging and RPC kinds neutral', () => {
    renderUi(<><MethodBadge method="DELETE" /><MethodBadge method="KAFKA" /></>);
    expect(screen.getByText('DELETE')).toHaveClass('text-deny');
    expect(screen.getByText('KAFKA')).toHaveClass('text-muted-foreground');
  });

  it('show an endpoint as its method and route, or as the text alone when it names no method', () => {
    renderUi(<><Endpoint text="POST /owners/{id}/pets" /><Endpoint text="scheduled" /></>);
    expect(screen.getByText('POST')).toBeInTheDocument();
    expect(screen.getByText('/owners/{id}/pets').tagName).toBe('CODE');
    expect(screen.getByText('scheduled').previousSibling).toBeNull();
  });

  it('show no requirement as No Authorization, a requirement whole on hover, and nothing when none is known', async () => {
    const { user, container } = renderUi(<><RequirementBadge requirement="none" />
      <RequirementBadge requirement="SCOPE_profiles.read and ROLE_USER" /><RequirementBadge requirement={undefined} /></>);
    expect(screen.getByText('No Authorization')).toBeInTheDocument();
    await user.hover(screen.getByText('SCOPE_profiles.read and ROLE_USER'));
    expect(await screen.findByRole('tooltip')).toHaveTextContent('SCOPE_profiles.read and ROLE_USER');
    expect(container.querySelectorAll('span.truncate')).toHaveLength(1);
  });

  it('head a view with its title and description, and its controls when it has any', () => {
    renderUi(<><ViewHeader title="Plain" description="No controls" /><ViewHeader title="Controlled" description="With one">
      <button type="button">Control</button></ViewHeader></>);
    expect(screen.getByRole('heading', { name: 'Plain' }).parentElement!.nextElementSibling).toBeNull();
    expect(screen.getByRole('button', { name: 'Control' })).toBeInTheDocument();
  });
});
