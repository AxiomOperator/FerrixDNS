import { useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";

import { ErrorState, Loading, PageHeader, ReadOnlyNotice } from "@/components/states";
import { Card, CardHeader } from "@/components/ui/card";
import { Input } from "@/components/ui/form";
import { Switch } from "@/components/ui/switch";
import { type BlockedService, type Group, api, queries, usePolicyMutation } from "@/lib/api/hooks";

function ServiceRow({
  service,
  groups,
  readOnly,
}: {
  service: BlockedService;
  groups: Group[];
  readOnly: boolean;
}) {
  const save = usePolicyMutation(
    (change: { blocked: boolean; groups: string[] }) => api.setBlockedService(service.id, change),
    (saved) => (saved.blocked ? `${saved.name} is blocked` : `${saved.name} is no longer blocked`),
  );
  const who =
    service.groups.length > 0 ? `Blocked for ${service.groups.join(", ")}` : "Blocked for everyone";

  return (
    <li className="px-4 py-3">
      <div className="flex items-start gap-3">
        <div className="pt-0.5">
          <Switch
            label={`Block ${service.name}`}
            checked={service.blocked}
            disabled={readOnly || save.isPending}
            onCheckedChange={(blocked) => save.mutate({ blocked, groups: [] })}
          />
        </div>
        <div className="min-w-0 flex-1">
          <p className="text-sm font-medium">{service.name}</p>
          <p className="text-xs text-text-muted">{service.blocked ? who : `${service.domains.length} domains`}</p>
          {service.blocked && groups.length > 0 && (
            <fieldset className="mt-2 flex flex-wrap gap-x-4 gap-y-1">
              <legend className="sr-only">Who {service.name} is blocked for</legend>
              {groups.map((group) => (
                <label key={group.id} className="flex items-center gap-1.5 text-xs text-text-secondary">
                  <input
                    type="checkbox"
                    disabled={readOnly || save.isPending}
                    checked={service.groups.includes(group.id)}
                    onChange={(event) =>
                      save.mutate({
                        blocked: true,
                        groups: event.target.checked
                          ? [...service.groups, group.id]
                          : service.groups.filter((id) => id !== group.id),
                      })
                    }
                  />
                  {group.id}
                </label>
              ))}
            </fieldset>
          )}
        </div>
      </div>
    </li>
  );
}

export function ServicesPage({ readOnly }: { readOnly: boolean }) {
  const services = useQuery(queries.blockedServices());
  const groups = useQuery(queries.groups());
  const [search, setSearch] = useState("");

  const categories = useMemo(() => {
    const term = search.trim().toLowerCase();
    const grouped = new Map<string, BlockedService[]>();
    for (const service of services.data ?? []) {
      const matches =
        !term ||
        service.name.toLowerCase().includes(term) ||
        service.domains.some((domain) => domain.includes(term));
      if (matches) grouped.set(service.category, [...(grouped.get(service.category) ?? []), service]);
    }
    return [...grouped.entries()];
  }, [services.data, search]);

  const blockedCount = services.data?.filter((service) => service.blocked).length ?? 0;

  return (
    <>
      <PageHeader
        title="Blocked services"
        description="Block well-known services in one step. With no groups ticked, a service is blocked for everyone. An allow rule still makes an exception for one name."
      />
      {readOnly && <ReadOnlyNotice />}
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <div className="w-full max-w-xs">
          <label htmlFor="service-search" className="sr-only">
            Search services
          </label>
          <Input
            id="service-search"
            placeholder="Search services…"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
          />
        </div>
        <p role="status" className="text-sm text-text-secondary">
          {blockedCount === 1 ? "1 service blocked" : `${blockedCount} services blocked`}
        </p>
      </div>
      {services.isPending && <Loading />}
      {services.isError && <ErrorState error={services.error} onRetry={() => void services.refetch()} />}
      {services.data && categories.length === 0 && (
        <p className="py-6 text-center text-sm text-text-muted">No service matches that.</p>
      )}
      <div className="grid items-start gap-4 lg:grid-cols-2">
        {categories.map(([category, items]) => (
          <Card key={category}>
            <CardHeader title={category} />
            <ul className="divide-y divide-border border-t border-border">
              {items.map((service) => (
                <ServiceRow
                  key={service.id}
                  service={service}
                  groups={groups.data ?? []}
                  readOnly={readOnly}
                />
              ))}
            </ul>
          </Card>
        ))}
      </div>
      <p className="mt-3 text-xs text-text-muted">
        These cover each service's main domains. Services change their domains over time, and an app may
        keep working from answers devices have already cached.
      </p>
    </>
  );
}
