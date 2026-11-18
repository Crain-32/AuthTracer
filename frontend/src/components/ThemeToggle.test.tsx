import { screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { renderUi } from '@/test/render';

import { ThemeToggle } from './ThemeToggle';

afterEach(() => vi.restoreAllMocks());

describe('ThemeToggle', () => {
  it('switches to the dark theme and back, and remembers the choice', async () => {
    const { user } = renderUi(<ThemeToggle />);
    const toggle = screen.getByRole('button', { name: 'Toggle theme' });
    await user.hover(toggle);
    expect(await screen.findByRole('tooltip')).toHaveTextContent('Dark theme');
    await user.click(toggle);
    expect(document.documentElement).toHaveClass('dark');
    expect(localStorage.getItem('authtracer.theme')).toBe('dark');
    await user.click(toggle);
    expect(document.documentElement).not.toHaveClass('dark');
    expect(localStorage.getItem('authtracer.theme')).toBe('light');
  });

  it('starts from the theme the page loaded with', async () => {
    document.documentElement.classList.add('dark');
    const { user } = renderUi(<ThemeToggle />);
    await user.hover(screen.getByRole('button', { name: 'Toggle theme' }));
    expect(await screen.findByRole('tooltip')).toHaveTextContent('Light theme');
  });

  it('still switches when the browser keeps no storage', async () => {
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new DOMException('The quota has been exceeded', 'QuotaExceededError');
    });
    const { user } = renderUi(<ThemeToggle />);
    await user.click(screen.getByRole('button', { name: 'Toggle theme' }));
    expect(document.documentElement).toHaveClass('dark');
  });
});
