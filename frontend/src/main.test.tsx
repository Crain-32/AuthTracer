import { screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { stubServer } from '@/test/server';

describe('main', () => {
  it('mounts the app into the page\'s root, with the tooltips it needs', async () => {
    stubServer({});
    document.body.innerHTML = '<div id="root"></div>';
    await import('./main');
    expect(await screen.findByRole('heading', { name: 'No graph loaded yet' })).toBeInTheDocument();
    expect(document.getElementById('root')).toContainElement(screen.getByRole('navigation'));
  });
});
