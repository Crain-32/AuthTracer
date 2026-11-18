// @supports LINEAGE_VIEW
import { GitBranch } from 'lucide-react';
import { useEffect, useMemo } from 'react';

import { EmptyState, ViewHeader } from '@/components/common';
import { Card } from '@/components/ui/card';
import { Select } from '@/components/ui/select';
import type { Model } from '@/lib/model';
import { useUi } from '@/lib/store';
import type { Exposure } from '@/lib/types';
import { groupBy } from '@/lib/utils';

import { ExposureTable } from '../exposures/ExposureTable';
import { LineageDiagram } from './LineageDiagram';

function keyOf(exposure: Exposure): string {
  return `${exposure.service}|${exposure.ingress}`;
}

/**
 * Where an endpoint's response fields come from. One box per class with a row per field, sources on the left, the
 * response on the right; fields copied unchanged share one arrow, so the arrows that remain are the differences.
 */
export function LineageView({ model }: { model: Model }) {
  const state = useUi(store => store.lineage);
  const setLineage = useUi(store => store.setLineage);
  const endpoints = useMemo(() => model.exposures.filter(exposure => exposure.field === ''), [model]);
  const fieldsByEndpoint = useMemo(() => groupBy(model.exposures.filter(exposure => exposure.field !== ''), keyOf),
    [model]);
  const known = endpoints.some(endpoint => keyOf(endpoint) === state.endpoint);
  useEffect(() => {
    if (!known && endpoints.length) {
      // The endpoint with the most to show: the most flows behind its fields.
      const flows = (endpoint: Exposure) => (fieldsByEndpoint.get(keyOf(endpoint)) ?? [])
        .reduce((sum, field) => sum + field.lineage.length, 0);
      const richest = [...endpoints].sort((a, b) => flows(b) - flows(a))[0];
      setLineage({ endpoint: keyOf(richest), field: '' });
    }
  }, [known, endpoints, fieldsByEndpoint, setLineage]);
  const fields = useMemo(() => fieldsByEndpoint.get(state.endpoint ?? '') ?? [], [fieldsByEndpoint, state.endpoint]);
  const shown = useMemo(() => fields.filter(field => !state.field || field.field === state.field), [fields, state.field]);
  const endpoint = endpoints.find(found => keyOf(found) === state.endpoint);
  if (!endpoints.length) {
    return <EmptyState icon={<GitBranch />} title="No endpoints">This graph has no endpoints to trace.</EmptyState>;
  }
  return (
    <div>
      <ViewHeader title="Field lineage"
        description="Where each response field comes from, left to right from its sources to the response. Fields copied
          unchanged between classes share one arrow; renames, computed values and field checks stand out.">
        <Select label="Endpoint" value={state.endpoint ?? ''} onChange={value => setLineage({ endpoint: value, field: '' })}
          className="w-80" options={endpoints.map(found => ({ value: keyOf(found), label: `${found.service}  ${found.endpoint}` }))} />
        <Select label="Field" value={state.field} onChange={field => setLineage({ field })} className="w-56"
          options={[{ value: '', label: `All response fields (${fields.length})` },
            ...fields.map(field => ({ value: field.field, label: field.field }))]} />
      </ViewHeader>
      {shown.length ? (
        <Card className="mb-6 overflow-hidden p-1"><LineageDiagram model={model} exposures={shown} /></Card>
      ) : (
        <div className="mb-6">
          <EmptyState icon={<GitBranch />} title="No response fields">This endpoint returns no fields the scan could see.</EmptyState>
        </div>
      )}
      <h3 className="mb-2 text-sm font-semibold">What a caller needs, per field</h3>
      <ExposureTable exposures={[endpoint, ...shown].filter((found): found is Exposure => !!found)} />
    </div>
  );
}
