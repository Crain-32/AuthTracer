// @supports PATHS_VIEW
import * as Collapsible from '@radix-ui/react-collapsible';
import { ChevronRight, ChevronsDownUp, ChevronsUpDown, PlugZap, Route, Search } from 'lucide-react';
import { useMemo } from 'react';

import { Endpoint, EmptyState, RequirementBadge, ServiceTag, ViewHeader } from '@/components/common';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Select } from '@/components/ui/select';
import { Switch } from '@/components/ui/switch';
import { Tip } from '@/components/ui/tooltip';
import { count, endpointText, payload } from '@/lib/format';
import { serviceOf, type Model } from '@/lib/model';
import { useUi } from '@/lib/store';
import { cn, commonPrefix } from '@/lib/utils';

import { PathDiagram } from './PathDiagram';
import { isBare, matches, mergePaths, runs, servicesOf, type Group, type Root } from './pathGroups';
import { drawOrder, layout } from './pathLayout';

/** More endpoints alike than this in a card's list are summed up in one line. */
const MAX_LINES = 3;

/**
 * Every Ingress's request path, steps left to right in time order, one lane per service. Endpoints whose paths end
 * the same way share one card, and the shared steps are drawn once, so what differs between them stands out.
 */
export function PathsView({ model }: { model: Model }) {
  const state = useUi(store => store.paths);
  const setPaths = useUi(store => store.setPaths);
  const services = useMemo(() => (state.service ? [state.service] : model.services), [model, state.service]);
  const groups = useMemo(() => mergePaths(model, services.flatMap(service => model.ingresses(service)), state.follow),
    [model, services, state.follow]);
  const words = state.search.toLowerCase().split(/\s+/).filter(Boolean);
  const shown = groups.filter(group => matches(model, group, words));
  const allOpen = shown.length > 0 && shown.every(group => state.open.has(group.key));
  const toggle = (key: string, open: boolean) => {
    const next = new Set(state.open);
    if (open) {
      next.add(key);
    }
    else {
      next.delete(key);
    }
    setPaths({ open: next });
  };
  const endpoints = groups.reduce((sum, group) => sum + [group, ...group.twins]
    .reduce((members, member) => members + member.roots.length, 0), 0);

  return (
    <div>
      <ViewHeader title="Request paths"
        description="Each endpoint's checks and calls in the order they run. A called service's checks run before the
          caller's next step. Endpoints whose paths end the same way share a card, drawn once, so the differences stand out.">
        <div className="relative">
          <Search className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input value={state.search} onChange={event => setPaths({ search: event.target.value })}
            placeholder="Filter endpoints…" className="w-56 pl-8" aria-label="Filter endpoints" />
        </div>
        <Select label="Service" value={state.service} onChange={service => setPaths({ service })} className="w-44"
          options={[{ value: '', label: 'All services' }, ...model.services.map(service => ({ value: service, label: service }))]} />
        <Switch checked={state.follow} onChange={follow => setPaths({ follow })}>Follow calls into services</Switch>
        <Button variant="outline" size="sm" onClick={() => setPaths({ open: allOpen ? new Set()
          : new Set([...state.open, ...shown.map(group => group.key)]) })}>
          {allOpen ? <ChevronsDownUp /> : <ChevronsUpDown />}
          {allOpen ? 'Collapse all' : 'Expand all'}
        </Button>
      </ViewHeader>
      <p className="mb-3 text-xs text-muted-foreground">
        {count(endpoints, 'endpoint')} in {count(groups.length, 'card')}
        {words.length ? `; ${shown.length} match the filter` : ''}
      </p>
      {shown.length ? (
        <div className="flex flex-col gap-2.5">
          {shown.map(group => (
            <PathCard key={group.key} model={model} group={group} open={state.open.has(group.key)}
              onOpenChange={open => toggle(group.key, open)} />
          ))}
          <OutsideRequests model={model} services={services} />
        </div>
      ) : (
        <EmptyState icon={<Route />} title="No endpoints match">Try another filter or service.</EmptyState>
      )}
    </div>
  );
}

function PathCard({ model, group, open, onOpenChange }: { model: Model; group: Group; open: boolean;
  onOpenChange: (open: boolean) => void }) {
  const select = useUi(state => state.select);
  const plan = useMemo(() => layout(group), [group]);
  const roots = useMemo(() => drawOrder(group, plan), [group, plan]);
  const bare = isBare(group);
  const services = servicesOf(group);
  const serviceLabel = services.length > 3 ? `${services.length} services` : services.join(', ');
  return (
    <Collapsible.Root open={open} onOpenChange={onOpenChange} asChild>
      <Card className={cn('overflow-hidden transition-shadow', open && 'shadow-md')}>
        <Collapsible.Trigger asChild>
          <button className="flex w-full cursor-pointer items-start gap-3 px-4 py-3 text-left hover:bg-muted/50">
            <ChevronRight className={cn('mt-1 size-4 shrink-0 text-muted-foreground transition-transform',
              open && 'rotate-90')} />
            <div className="grid min-w-0 flex-1 grid-cols-[9.5rem_minmax(12rem,1fr)_minmax(0,24rem)_13rem] items-center
              gap-x-4 gap-y-1.5">
              {runs(model, roots).flatMap(run => run.length > MAX_LINES
                ? [<RunLine key={run[0].ingress} model={model} run={run} service={services.length > 1 ? serviceLabel : undefined}
                  title={services.join('\n')} />]
                : run.map(root => <CardLine key={root.ingress} model={model} root={root}
                  service={services.length > 1 ? serviceLabel : undefined} title={services.join('\n')} />))}
            </div>
          </button>
        </Collapsible.Trigger>
        <Collapsible.Content>
          <div className="border-t bg-background/40">
            {bare ? (
              <ul className="columns-[18rem] gap-6 px-5 py-3">
                {roots.map(root => {
                  const ingress = model.node(root.ingress);
                  return (
                    <li key={root.ingress} className="break-inside-avoid py-0.5">
                      <button className="cursor-pointer rounded px-1 text-left hover:bg-muted"
                        onClick={() => select({ type: 'node', qid: root.ingress })}>
                        {ingress?.type === 'ingress' && <Endpoint text={endpointText(ingress)} className="text-sm" />}
                      </button>
                    </li>
                  );
                })}
              </ul>
            ) : open && <PathDiagram model={model} group={group} plan={plan} />}
            {group.twins.length > 0 && (
              <p className="px-5 pb-3 text-xs text-muted-foreground">
                Drawn for {services[0]}; the same in {services.slice(1).join(', ')}.
              </p>
            )}
          </div>
        </Collapsible.Content>
      </Card>
    </Collapsible.Root>
  );
}

/** One endpoint: what it requires, and how many checks stand in front of it. */
function CardLine({ model, root, service, title }: { model: Model; root: Root; service?: string; title?: string }) {
  const ingress = model.node(root.ingress);
  const exposure = model.endpointExposure(root.ingress);
  const callers = [...new Set(model.linksTo(root.ingress).map(link => serviceOf(link.from)))];
  return (
    <>
      <ServiceTag title={service ? title : undefined}>{service ?? serviceOf(root.ingress)}</ServiceTag>
      <Tip content={ingress?.type === 'ingress' && ingress.response ? `Returns ${payload(ingress.response)}` : undefined}>
        <span className="block min-w-0">
          {ingress?.type === 'ingress' && <Endpoint text={endpointText(ingress)} className="flex max-w-full text-sm" />}
        </span>
      </Tip>
      <RequirementBadge requirement={exposure?.requirement} className="max-w-full justify-self-start" />
      <Meta checks={root.checks} callers={callers} />
    </>
  );
}

/** Many endpoints that read the same, as one line: how many, under which common path; the tooltip lists them. */
function RunLine({ model, run, service, title }: { model: Model; run: Root[]; service?: string; title?: string }) {
  const routes = run.map(root => {
    const ingress = model.node(root.ingress);
    return ingress?.type === 'ingress' ? ingress.route : '';
  });
  const under = commonPrefix(routes);
  const first = run[0];
  const callers = [...new Set(model.linksTo(first.ingress).map(link => serviceOf(link.from)))];
  const list = run.map(root => {
    const ingress = model.node(root.ingress);
    return ingress?.type === 'ingress' ? endpointText(ingress) : root.ingress;
  }).join('\n');
  return (
    <>
      <ServiceTag title={service ? title : undefined}>{service ?? serviceOf(first.ingress)}</ServiceTag>
      <Tip content={list}>
        <span className="truncate text-sm font-medium">
          {run.length} endpoints{under && <> under <code>{under}</code></>}
        </span>
      </Tip>
      <RequirementBadge requirement={model.endpointExposure(first.ingress)?.requirement}
        className="max-w-full justify-self-start" />
      <Meta checks={first.checks} callers={callers} />
    </>
  );
}

function Meta({ checks, callers }: { checks: number; callers: string[] }) {
  return (
    <Tip content={callers.length ? `Called by ${callers.join(', ')}` : undefined}>
      <span className="truncate text-right text-xs text-muted-foreground">
        {count(checks, 'check')}
        {callers.length > 0 && <> · called by {callers.join(', ')}</>}
      </span>
    </Tip>
  );
}

/** The calls services make outside any request, with the services they reach: one quiet card, after the paths. */
function OutsideRequests({ model, services }: { model: Model; services: string[] }) {
  const select = useUi(state => state.select);
  const rows = services.flatMap(service => model.offPathEgresses(service).map(qid => ({ service, qid })));
  if (!rows.length) {
    return null;
  }
  return (
    <Collapsible.Root asChild>
      <Card className="overflow-hidden">
        <Collapsible.Trigger asChild>
          <button className="group flex w-full cursor-pointer items-center gap-3 px-4 py-3 text-left text-sm
            text-muted-foreground hover:bg-muted/50">
            <ChevronRight className="size-4 transition-transform group-data-[state=open]:rotate-90" />
            <PlugZap className="size-4" />
            Calls outside requests (token checks, configuration, discovery): {rows.length}
          </button>
        </Collapsible.Trigger>
        <Collapsible.Content>
          <ul className="grid gap-1 border-t px-5 py-3 text-sm">
            {rows.map(({ service, qid }) => {
              const egress = model.node(qid);
              const targets = [...new Set(model.linksFrom(qid).map(link => serviceOf(link.to)))];
              return egress?.type === 'egress' && (
                <li key={qid}>
                  <button className="flex cursor-pointer flex-wrap items-center gap-2 rounded px-1 text-left hover:bg-muted"
                    onClick={() => select({ type: 'node', qid })}>
                    <ServiceTag>{service}</ServiceTag>
                    <span className="text-muted-foreground">{egress.client}</span>
                    <Endpoint text={`${egress.httpMethod} ${egress.uriTemplate}`} />
                    <span className="text-muted-foreground">
                      → {targets.length ? targets.join(', ') : 'no scanned service'}
                    </span>
                  </button>
                </li>
              );
            })}
          </ul>
        </Collapsible.Content>
      </Card>
    </Collapsible.Root>
  );
}
