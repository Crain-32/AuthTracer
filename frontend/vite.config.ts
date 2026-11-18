import { fileURLToPath, URL } from 'node:url';

import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import { defineConfig } from 'vitest/config';

// Gradle's processResources picks the build up from build/frontend (static/ is Spring Boot's static resource root).
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: { alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) } },
  build: {
    outDir: '../build/frontend/static',
    emptyOutDir: true,
    chunkSizeWarningLimit: 1500,
  },
  server: {
    // npm run dev against a running AuthTracer server.
    // The server listens on 127.0.0.1 only; Node may resolve localhost to ::1 first.
    proxy: { '/api': 'http://127.0.0.1:8080' },
  },
  test: {
    // The logic's tests (.test.ts) run in Node; the components' (.test.tsx) in jsdom, with what it lacks stubbed.
    projects: [
      { extends: true, test: { name: 'logic', include: ['src/**/*.test.ts'], environment: 'node' } },
      { extends: true, test: { name: 'ui', include: ['src/**/*.test.tsx'], environment: 'jsdom',
        setupFiles: ['src/test/setup.ts'] } },
    ],
    coverage: {
      provider: 'v8',
      include: ['src/**/*.{ts,tsx}'],
      exclude: ['src/**/*.test.{ts,tsx}', 'src/test/**'],
      reporter: ['text', 'html', 'json-summary'],
      // A little below what the tests reach (100% of lines, 98.9% of branches), so a drop fails npm run coverage.
      thresholds: { lines: 99, statements: 99, functions: 99, branches: 97 },
    },
  },
});
