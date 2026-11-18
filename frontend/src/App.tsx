// @supports UI
import {
  AlertTriangle, BookOpen, Cable, Database, FileDiff, FileUp, Fingerprint, GitBranch, Loader2, Route,
  ShieldCheck, Table2, Upload,
} from 'lucide-react';
import { useCallback, useEffect, useRef, useState, type ComponentType, type DragEvent } from 'react';

import { EmptyState } from '@/components/common';
import { ErrorBoundary } from '@/components/ErrorBoundary';
import { ThemeToggle } from '@/components/ThemeToggle';
import { Button } from '@/components/ui/button';
import { Select } from '@/components/ui/select';
import { Tip } from '@/components/ui/tooltip';
import { DetailsPanel } from '@/features/details/DetailsPanel';
import { DiffView } from '@/features/diff/DiffView';
import { ExposuresView } from '@/features/exposures/ExposuresView';
import { FindingsView } from '@/features/findings/FindingsView';
import { IdentitiesView } from '@/features/identities/IdentitiesView';
import { LegendView } from '@/features/legend/LegendView';
import { LineageView } from '@/features/lineage/LineageView';
import { PathsView } from '@/features/paths/PathsView';
import { linkStored, loadService, loadSystem, openFile, RequestError, storedServices } from '@/lib/api';
import type { Model } from '@/lib/model';
import { useUi, type ViewId } from '@/lib/store';
import { cn } from '@/lib/utils';

interface ViewSpec {
  title: string;
  icon: ComponentType<{ className?: string }>;
  badge?: (model: Model) => number;
}

const VIEWS: Record<ViewId, ViewSpec> = {
  paths: { title: 'Request paths', icon: Route },
  lineage: { title: 'Field lineage', icon: GitBranch },
  exposures: { title: 'Exposures', icon: Table2 },
  findings: { title: 'Findings', icon: AlertTriangle, badge: model => model.findings().length },
  identities: { title: 'Identities', icon: Fingerprint },
  diff: { title: 'Diff report', icon: FileDiff },
  legend: { title: 'Legend', icon: BookOpen },
};

const isView = (value: string): value is ViewId => Object.hasOwn(VIEWS, value);

/** What went wrong, as a person reads it. */
const messageOf = (error: unknown) => (error instanceof Error ? error.message : String(error));

export function App() {
  // One selector each, so typing in a view's filter doesn't re-render the shell.
  const model = useUi(state => state.model);
  const view = useUi(state => state.view);
  const selection = useUi(state => state.selection);
  const status = useUi(state => state.status);
  const show = useUi(state => state.show);
  const loadModel = useUi(state => state.loadModel);
  const loadDiff = useUi(state => state.loadDiff);
  const setStatus = useUi(state => state.setStatus);
  const [services, setServices] = useState<string[] | null>(null);
  const [dragging, setDragging] = useState(false);
  const file = useRef<HTMLInputElement>(null);
  // Loads can overlap (the latest graph at startup, a file dropped meanwhile): only the newest one's result counts.
  const loads = useRef(0);

  const fail = useCallback((error: unknown) => setStatus({ text: messageOf(error), error: true }), [setStatus]);

  const latest = useCallback(async () => {
    const load = ++loads.current;
    setStatus({ text: 'Loading the latest system graph…', busy: true });
    try {
      const loaded = await loadSystem();
      if (load === loads.current) {
        loadModel(loaded);
      }
    }
    catch (error) {
      if (load !== loads.current) {
        return;
      }
      if (error instanceof RequestError && error.status === 404) {
        setStatus({ text: 'No system graph stored yet: publish graphs and link them, or open a file.' });
      }
      else {
        fail(error);
      }
    }
  }, [loadModel, setStatus, fail]);

  // A load too: a graph the person opens while the link runs stays, and the link's outcome no longer counts.
  const link = async () => {
    const load = ++loads.current;
    setStatus({ text: 'Linking the stored graphs with the trace store…', busy: true });
    try {
      await linkStored();
    }
    catch (error) {
      if (load !== loads.current) {
        return;
      }
      if (error instanceof RequestError && error.status === 422) {
        setStatus({ text: 'No graphs stored yet: publish them with scan --publish http://localhost:8080', error: true });
      }
      else {
        fail(error);
      }
      return;
    }
    if (load === loads.current) {
      await latest();
    }
  };

  const service = async (name: string) => {
    const load = ++loads.current;
    setStatus({ text: `Loading ${name}…`, busy: true });
    try {
      const loaded = await loadService(name);
      if (load === loads.current) {
        loadModel(loaded);
      }
    }
    catch (error) {
      if (load === loads.current) {
        fail(error);
      }
    }
  };

  const open = async (files: FileList | File[]) => {
    for (const opened of [...files]) {
      try {
        const result = await openFile(opened);
        if (result.kind === 'diff') {
          loadDiff(result.report, opened.name);
          setStatus({ text: `Diff report ${opened.name} loaded` });
        }
        else {
          // A graph the person picked wins over a load still on its way.
          loads.current++;
          loadModel(result.model);
        }
      }
      catch (error) {
        setStatus({ text: `${opened.name}: ${messageOf(error)}`, error: true });
      }
    }
  };

  useEffect(() => {
    storedServices().then(setServices, () => setServices(null));
    latest();
  }, [latest]);

  // The view follows the URL's hash, so a view can be linked to and the back button works.
  useEffect(() => {
    const fromHash = () => {
      const hash = location.hash.slice(1);
      if (isView(hash)) {
        show(hash);
      }
    };
    fromHash();
    addEventListener('hashchange', fromHash);
    return () => removeEventListener('hashchange', fromHash);
  }, [show]);
  // A view opened from code (a diff file, "Show its lineage") gets its own history entry, so Back returns.
  useEffect(() => {
    if (location.hash.slice(1) !== view) {
      if (location.hash) {
        history.pushState(null, '', `#${view}`);
      }
      else {
        history.replaceState(null, '', `#${view}`);
      }
    }
  }, [view]);

  const onDrop = (event: DragEvent) => {
    event.preventDefault();
    setDragging(false);
    if (event.dataTransfer.files.length) {
      open(event.dataTransfer.files);
    }
  };

  return (
    <div className="flex h-screen overflow-hidden" onDrop={onDrop}
      onDragOver={event => {
        if (event.dataTransfer.types.includes('Files')) {
          event.preventDefault();
          setDragging(true);
        }
      }}
      onDragLeave={event => {
        if (!event.currentTarget.contains(event.relatedTarget as Node | null)) {
          setDragging(false);
        }
      }}>
      <nav className="flex w-60 shrink-0 flex-col border-r bg-card">
        <div className="flex items-center gap-2.5 px-5 pt-5 pb-6">
          <div className="grid size-8 place-items-center rounded-lg bg-primary text-primary-foreground shadow-sm">
            <ShieldCheck className="size-4.5" />
          </div>
          <div>
            <div className="text-[15px] font-semibold tracking-tight">AuthTracer</div>
            <div className="text-[11px] text-muted-foreground">Authorization graph</div>
          </div>
        </div>
        <div className="flex flex-1 flex-col gap-0.5 px-3">
          {(Object.entries(VIEWS) as [ViewId, ViewSpec][]).map(([id, item]) => {
            const Icon = item.icon;
            const badge = model && item.badge?.(model);
            return (
              <a key={id} href={`#${id}`} onClick={() => show(id)}
                className={cn('flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors',
                  view === id ? 'bg-accent text-primary' : 'text-muted-foreground hover:bg-muted hover:text-foreground')}>
                <Icon className="size-4" />
                <span className="flex-1">{item.title}</span>
                {!!badge && <span className="rounded-full bg-deny-soft px-1.5 text-[11px] font-semibold text-deny">{badge}</span>}
              </a>
            );
          })}
        </div>
        <div className="flex items-center justify-between border-t px-4 py-3">
          <span className="text-[11px] text-muted-foreground">Static analysis of Spring apps</span>
          <ThemeToggle />
        </div>
      </nav>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex flex-wrap items-center gap-3 border-b bg-card/80 px-6 py-3 backdrop-blur">
          <Tip content="GET /api/system: the newest linked system graph">
            <Button variant="outline" size="sm" onClick={latest}><Database /> Latest system graph</Button>
          </Tip>
          <Tip content="POST /api/system/link: links the newest graph of every service with Zipkin's recent traces">
            <Button variant="outline" size="sm" onClick={link}><Cable /> Link stored graphs</Button>
          </Tip>
          <Select label="Stored service graph" value="" onChange={service} className="h-8 w-52"
            placeholder={services === null ? 'Server unavailable' : services.length ? 'Stored service graph…'
              : 'No stored service graphs'}
            options={(services ?? []).map(name => ({ value: name, label: name }))} />
          <Tip content="An application graph, a system graph, or a diff report (diff --json). You can also drop files on the page.">
            <Button variant="outline" size="sm" onClick={() => file.current?.click()}><FileUp /> Open file</Button>
          </Tip>
          <input ref={file} type="file" accept=".json,application/json" multiple hidden
            onChange={event => { if (event.target.files) { open(event.target.files); } event.target.value = ''; }} />
          {(status.busy || status.error || status.text !== model?.origin) && (
            <div className={cn('ml-auto flex min-w-0 items-center gap-2 text-sm', status.error ? 'text-deny'
              : 'text-muted-foreground')}>
              {status.busy && <Loader2 className="size-4 shrink-0 animate-spin" />}
              <span className="truncate">{status.text}</span>
            </div>
          )}
        </header>
        {model && <Stats model={model} />}

        <div className="flex min-h-0 flex-1">
          <main className="min-w-0 flex-1 overflow-y-auto px-6 py-6">
            <div className="mx-auto max-w-[1600px]">
              <ErrorBoundary resetKeys={[view, model]}><ViewBody view={view} model={model} /></ErrorBoundary>
            </div>
          </main>
          {selection && model && (
            <div className="w-[400px] shrink-0 border-l bg-card">
              <ErrorBoundary resetKeys={[selection, model]}>
                <DetailsPanel model={model} selection={selection} />
              </ErrorBoundary>
            </div>
          )}
        </div>
      </div>

      {dragging && (
        <div className="pointer-events-none fixed inset-0 z-50 grid place-items-center bg-primary/10 backdrop-blur-sm">
          <div className="rounded-2xl border-2 border-dashed border-primary bg-card px-10 py-8 text-center shadow-xl">
            <FileUp className="mx-auto mb-2 size-8 text-primary" />
            <div className="font-semibold">Drop graph or diff files</div>
          </div>
        </div>
      )}
    </div>
  );
}

function ViewBody({ view, model }: { view: ViewId; model: Model | null }) {
  switch (view) {
    case 'diff':
      return <DiffView />;
    case 'legend':
      return <LegendView />;
  }
  if (!model) {
    return (
      <EmptyState icon={<Upload />} title="No graph loaded yet">
        Load the latest system graph, a stored service graph, or open (or drop) a graph file.
      </EmptyState>
    );
  }
  switch (view) {
    case 'paths':
      return <PathsView model={model} />;
    case 'lineage':
      return <LineageView model={model} />;
    case 'exposures':
      return <ExposuresView model={model} />;
    case 'findings':
      return <FindingsView model={model} />;
    case 'identities':
      return <IdentitiesView model={model} />;
  }
}

/** The headline numbers of the loaded graph. */
function Stats({ model }: { model: Model }) {
  const stats = model.stats();
  const services = model.system.services.map(graph => `${graph.service}@${graph.revision}`).join('\n');
  const items: [string, number, string?, string?][] = [
    ['Services', stats.services, services],
    ['Endpoints', stats.endpoints],
    ['No Authorization', stats.open, 'Endpoints any caller reaches', stats.open ? 'text-deny' : undefined],
    ['Links', stats.links, `${stats.observed} observed in traces`],
    ['Findings', stats.findings, undefined, stats.findings ? 'text-request' : undefined],
  ];
  return (
    <div className="flex flex-wrap items-center gap-x-8 gap-y-2 border-b bg-card/50 px-6 py-2.5">
      <span className="truncate text-xs font-medium text-muted-foreground">{model.origin}</span>
      {items.map(([label, value, title, tone]) => (
        <Tip key={label} content={title}>
          <div className="flex items-baseline gap-1.5">
            <span className={cn('text-base font-semibold tabular-nums', tone)}>{value}</span>
            <span className="text-xs text-muted-foreground">{label}</span>
          </div>
        </Tip>
      ))}
    </div>
  );
}
