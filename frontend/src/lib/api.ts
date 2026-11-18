// @supports UI
import { asSystem, kindOf, Model } from './model';
import type { ApplicationGraph, DiffReport, Exposure, Snapshot, SystemGraph } from './types';

export class RequestError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
  }
}

function clip(text: string, max: number): string {
  return text.length > max ? text.slice(0, max - 1) + '…' : text;
}

async function request<T>(url: string, options?: RequestInit): Promise<T> {
  const response = await fetch(url, options);
  if (!response.ok) {
    const body = await response.text();
    let reason = body;
    try {
      const problem = JSON.parse(body);
      reason = problem.detail ?? problem.message ?? problem.error ?? body;
    }
    catch {
      // Not JSON: show the text as is.
    }
    throw new RequestError(`${options?.method ?? 'GET'} ${url}: ${response.status} ${clip(reason, 300)}`, response.status);
  }
  return response.json() as Promise<T>;
}

function exposuresOf(graph: SystemGraph | ApplicationGraph): Promise<Exposure[]> {
  return request('/api/exposures', { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(graph) });
}

/** The newest stored system graph, with its exposures. */
export async function loadSystem(): Promise<Model> {
  const system = await request<SystemGraph>('/api/system');
  return new Model(system, await request<Exposure[]>('/api/system/exposures'), 'Latest stored system graph');
}

export async function loadService(service: string): Promise<Model> {
  const graph = await request<ApplicationGraph>(`/api/graphs/${encodeURIComponent(service)}`);
  return new Model(asSystem(graph), await exposuresOf(graph), `Stored graph of ${service}`);
}

/** Links the newest graph of every service with the trace store's recent traces. */
export async function linkStored(): Promise<void> {
  await request('/api/system/link', { method: 'POST' });
}

export async function storedServices(): Promise<string[]> {
  const snapshots = await request<Snapshot[]>('/api/graphs');
  return [...new Set(snapshots.filter(snapshot => snapshot.kind === 'APPLICATION').map(snapshot => snapshot.service))].sort();
}

export type Opened = { kind: 'model'; model: Model } | { kind: 'diff'; report: DiffReport };

/** A file the user opened: an application graph, a system graph, or a diff report. */
export async function openFile(file: File): Promise<Opened> {
  const json = JSON.parse(await file.text());
  const kind = kindOf(json);
  if (kind === 'diff') {
    return { kind: 'diff', report: json as DiffReport };
  }
  if (kind) {
    return { kind: 'model', model: new Model(asSystem(json), await exposuresOf(json), `File ${file.name}`) };
  }
  throw new Error(`${file.name} is not an application graph, a system graph or a diff report`);
}
