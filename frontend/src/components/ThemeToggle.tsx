// @supports UI
import { Moon, Sun } from 'lucide-react';
import { useState } from 'react';

import { Button } from '@/components/ui/button';
import { Tip } from '@/components/ui/tooltip';

function store(theme: 'light' | 'dark') {
  try {
    localStorage.setItem('authtracer.theme', theme);
  }
  catch {
    // No storage: the choice lasts until the page reloads.
  }
}

export function ThemeToggle() {
  const [dark, setDark] = useState(() => document.documentElement.classList.contains('dark'));
  const toggle = () => {
    const next = !dark;
    document.documentElement.classList.toggle('dark', next);
    store(next ? 'dark' : 'light');
    setDark(next);
  };
  return (
    <Tip content={dark ? 'Light theme' : 'Dark theme'}>
      <Button variant="ghost" size="icon-sm" onClick={toggle} aria-label="Toggle theme">{dark ? <Sun /> : <Moon />}</Button>
    </Tip>
  );
}
