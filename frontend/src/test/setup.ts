import '@testing-library/jest-dom/vitest';

import { cleanup } from '@testing-library/react';
import { afterEach, beforeEach } from 'vitest';

import { useUi } from '@/lib/store';

import { installBrowserStubs, layout, viewport } from './dom';

installBrowserStubs();

beforeEach(() => {
  useUi.setState(useUi.getInitialState(), true);
  layout.width = 1200;
  viewport.held = false;
  viewport.options = [];
  viewport.waiting = [];
  history.replaceState(null, '', '/');
});

afterEach(() => {
  cleanup();
  document.documentElement.classList.remove('dark');
  localStorage.clear();
});
