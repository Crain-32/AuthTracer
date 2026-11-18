// @supports EXPOSURES_VIEW
import { Search, Table2 } from 'lucide-react';
import { useMemo } from 'react';

import { EmptyState, ViewHeader } from '@/components/common';
import { Input } from '@/components/ui/input';
import type { Model } from '@/lib/model';
import { useUi } from '@/lib/store';

import { ExposureTable } from './ExposureTable';
import { matchesFilter } from './exposureRows';

/** One row per endpoint and per response field: what a caller needs to get it. */
export function ExposuresView({ model }: { model: Model }) {
  const filter = useUi(state => state.exposures.filter);
  const setExposures = useUi(state => state.setExposures);
  const { matched, shown } = useMemo(() => {
    const words = filter.toLowerCase().split(/\s+/).filter(Boolean);
    const matched = new Set(model.exposures.filter(exposure => matchesFilter(exposure, words)));
    // A field reads as part of its endpoint, so a matching field brings its endpoint's row along.
    const withFields = new Set([...matched].filter(exposure => exposure.field)
      .map(exposure => `${exposure.service} ${exposure.endpoint}`));
    const shown = model.exposures.filter(exposure => matched.has(exposure)
      || (!exposure.field && withFields.has(`${exposure.service} ${exposure.endpoint}`)));
    return { matched, shown };
  }, [model, filter]);
  return (
    <div>
      <ViewHeader title="Exposures"
        description="What a caller needs for each endpoint and each response field, through every service the request
          crosses. Click a row for the checks on the way.">
        <div className="relative">
          <Search className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input type="search" value={filter} onChange={event => setExposures({ filter: event.target.value })}
            placeholder="e.g. ssn, ROLE_ADMIN, PII" className="w-72 pl-8" aria-label="Filter exposures" />
        </div>
        <span className="text-sm text-muted-foreground">{matched.size} of {model.exposures.length} exposures</span>
      </ViewHeader>
      {matched.size ? <ExposureTable exposures={shown} />
        : <EmptyState icon={<Table2 />} title="Nothing matches">No exposure mentions every word of the filter.</EmptyState>}
    </div>
  );
}
