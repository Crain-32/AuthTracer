import { vi } from 'vitest';

export type Answer = (init: RequestInit | undefined) => Response | Promise<Response>;

export const json = (body: unknown, status = 200): Answer => () => new Response(JSON.stringify(body), { status });

/** An answer that waits until the test calls `send`. */
export function later(): { answer: Answer; send: (response: Response) => void } {
  let send: (response: Response) => void = () => {};
  const pending = new Promise<Response>(resolve => { send = resolve; });
  return { answer: () => pending, send };
}

/**
 * A stubbed AuthTracer server, answering by "METHOD path"; anything else is a 404. Routes can change while a test
 * runs; the returned mock records the requests.
 */
export function stubServer(routes: Record<string, Answer>) {
  const fetchStub = vi.fn(async (url: string, init?: RequestInit) =>
    (routes[`${init?.method ?? 'GET'} ${url}`] ?? (() => new Response('Not found', { status: 404 })))(init));
  vi.stubGlobal('fetch', fetchStub);
  return fetchStub;
}
