// @supports IDENTITIES_VIEW
import { Fingerprint } from 'lucide-react';

import { EmptyState, ViewHeader } from '@/components/common';
import { Badge } from '@/components/ui/badge';
import { Tip } from '@/components/ui/tooltip';
import type { Model } from '@/lib/model';
import { cn } from '@/lib/utils';

/**
 * What each identity in the traces was granted and which of it the checks on its requests needed (decision 0023).
 * Traces name no user, so an identity is a set of authorities; one holding authorities nothing needed is over-scoped
 * for the paths it exercised, which a test identity shouldn't be.
 */
export function IdentitiesView({ model }: { model: Model }) {
  const identities = model.system.identities;
  const header = (
    <ViewHeader title="Identities"
      description="What each identity in the traces was granted, and which of it the checks on its requests needed. Traces
        name no user, so identities with the same authorities are one row." />
  );
  if (!identities.length) {
    return (
      <div>
        {header}
        <EmptyState icon={<Fingerprint />} title="No identities">
          Identities come from traces: link the graphs with Zipkin ("Link stored graphs", or the link command with --zipkin).
        </EmptyState>
      </div>
    );
  }
  const types = new Set(identities.map(identity => identity.authenticationType)).size > 1;
  const authorities = (list: string[], variant: 'grant' | 'mask') => list.length
    ? <span className="flex flex-wrap gap-1">{list.map(authority => <Badge key={authority} variant={variant}>{authority}</Badge>)}</span>
    : <span className="text-muted-foreground">—</span>;
  return (
    <div>
      {header}
      <div className="overflow-x-auto rounded-xl border bg-card shadow-xs">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b bg-muted/50 text-left text-xs tracking-wide text-muted-foreground uppercase">
              {[types ? 'Type' : null, 'Requests', 'Needed', 'Not needed', 'Denied'].filter(Boolean).map(title => (
                <th key={title} className="px-4 py-2.5 font-medium">{title}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {identities.map(identity => (
              <tr key={identity.authenticationType + identity.authorities.join(',')}
                className={cn('border-b align-top last:border-b-0', identity.unneeded.length && 'bg-request-soft/40')}>
                {types && <td className="px-4 py-2.5">{identity.authenticationType}</td>}
                <td className="px-4 py-2.5">
                  <Tip content={identity.endpoints.join('\n')}>
                    <span>{identity.requests} on {identity.endpoints.length} endpoint{identity.endpoints.length === 1 ? '' : 's'}</span>
                  </Tip>
                </td>
                <td className="px-4 py-2.5">{authorities(identity.needed, 'grant')}</td>
                <td className="px-4 py-2.5">
                  {authorities(identity.unneeded, 'mask')}
                  {identity.unread > 0 && (
                    <div className="mt-1 text-xs text-muted-foreground">
                      {identity.unread} check{identity.unread === 1 ? '' : 's'} AuthTracer can't read might need these
                    </div>
                  )}
                </td>
                <td className={cn('px-4 py-2.5', identity.denied > 0 && 'font-semibold text-deny')}>{identity.denied || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
