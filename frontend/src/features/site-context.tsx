import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useRouterState } from "@tanstack/react-router";
import { useEffect, useSyncExternalStore } from "react";

import { Select } from "@/components/ui/form";
import { setApiSite } from "@/lib/api/client";
import { queries } from "@/lib/api/hooks";

const STORAGE_KEY = "ferrixdns-site";
/** What a site's policy pages load, which must not carry over to another site. */
const SITE_QUERY_KEYS = ["rules", "lists", "blocked-services", "clients", "groups", "zones", "records", "forwarders", "settings", "revisions"];
const SITE_ROUTES = ["/filtering", "/groups", "/clients", "/dns/", "/fleet/policy-settings"];

function storedSite(): string | undefined {
  try {
    return localStorage.getItem(STORAGE_KEY) ?? undefined;
  } catch {
    return undefined;
  }
}

let site = storedSite();
setApiSite(site);
const listeners = new Set<() => void>();

function chooseSite(next: string | undefined) {
  site = next;
  setApiSite(next);
  try {
    if (next) localStorage.setItem(STORAGE_KEY, next);
    else localStorage.removeItem(STORAGE_KEY);
  } catch {
    // Remembering the choice is only a convenience.
  }
  for (const listener of listeners) listener();
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

/** The site whose policy is being edited. */
export function useCurrentSite(): string | undefined {
  return useSyncExternalStore(subscribe, () => site);
}

/** Switches site, and forgets what was loaded for the last one. */
export function useChooseSite() {
  const client = useQueryClient();
  return (next: string | undefined) => {
    if (next === site) return;
    chooseSite(next);
    for (const key of SITE_QUERY_KEYS) client.removeQueries({ queryKey: [key] });
  };
}

export function SitePicker() {
  const sites = useQuery(queries.sites());
  const current = useCurrentSite();
  const choose = useChooseSite();
  const known = sites.data?.some((item) => item.id === current);

  useEffect(() => {
    if (sites.data && !known) choose(sites.data[0]?.id);
    // Only a change in what exists should run this.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sites.data, known]);

  if (!sites.data || sites.data.length === 0) {
    return <p className="px-2 pb-1 text-xs text-text-muted">Add a site to edit its policy.</p>;
  }
  return (
    <div className="px-2 pb-2">
      <label htmlFor="current-site" className="sr-only">
        Site to edit
      </label>
      <Select id="current-site" value={current ?? ""} onChange={(event) => choose(event.target.value)}>
        {sites.data.map((item) => (
          <option key={item.id} value={item.id}>
            {item.name}
          </option>
        ))}
      </Select>
    </div>
  );
}

/** Says which site a policy page is editing, and that changes wait for a deployment. */
export function SiteBanner() {
  const path = useRouterState({ select: (state) => state.location.pathname });
  const sites = useQuery(queries.sites());
  const current = useCurrentSite();
  if (!SITE_ROUTES.some((route) => path.startsWith(route))) return null;
  const selected = sites.data?.find((item) => item.id === current);
  if (!selected) return null;
  return (
    <div className="flex flex-wrap items-center gap-2 border-b border-border bg-surface-muted px-4 py-2 text-sm">
      <p className="min-w-0 flex-1">
        Editing <span className="font-medium">{selected.name}</span>.{" "}
        {selected.has_undeployed_changes
          ? "These changes haven't been deployed, so nodes aren't using them yet."
          : "Changes here reach nodes when you deploy them."}
      </p>
      <Link to="/fleet/sites" className="font-medium text-accent underline underline-offset-2">
        Deploy from Sites
      </Link>
    </div>
  );
}
