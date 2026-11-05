import {
  infiniteQueryOptions,
  queryOptions,
  useMutation,
  useQueryClient,
} from "@tanstack/react-query";
import { toast } from "sonner";

import { type Schemas, apiUrl, errorMessage, getData, request, sendData } from "./client";

export type Rule = Schemas["RuleDto"];
export type List = Schemas["ListDto"];
export type Client = Schemas["ClientDto"];
export type Group = Schemas["GroupDto"];
export type QueryEvent = Schemas["QueryEventDto"];
export type Settings = Schemas["SettingsDto"];
export type TestResult = Schemas["TestRuleResponse"];
export type LocalZone = Schemas["LocalZoneDto"];
export type LocalRecord = Schemas["LocalRecordDto"];
export type ForwardZone = Schemas["ForwardZoneDto"];
export type NetworkDevice = Schemas["NetworkDeviceDto"];
export type NodeSettings = Schemas["NodeSettings"];
export type NodeSettingsView = Schemas["NodeSettingsView"];
export type BlockedService = Schemas["BlockedServiceDto"];
export type Site = Schemas["SiteDto"];
export type FleetNode = Schemas["NodeDto"];
export type Deployment = Schemas["DeploymentDto"];

export interface QueryFilters {
  qname?: string;
  client?: string;
  action?: string;
  qtype?: string;
}

/** How often open pages update. Browsers pause this for tabs that aren't visible. */
const REFRESH_MS = 2_000;
/** A slow request gets this many times as long to rest, so a big history can't keep the node busy. */
const REST_FACTOR = 5;

const requestTimes = new Map<string, number>();

async function timed<T>(name: string, load: () => Promise<T>): Promise<T> {
  const started = performance.now();
  const result = await load();
  requestTimes.set(name, performance.now() - started);
  return result;
}

const pacedRefresh = (name: string) => () =>
  Math.max(REFRESH_MS, (requestTimes.get(name) ?? 0) * REST_FACTOR);

function queryString(values: Record<string, string | number | undefined>): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(values)) {
    if (value !== undefined && value !== "") params.set(key, String(value));
  }
  const text = params.toString();
  return text ? `?${text}` : "";
}

/** Where to download the query log, with the same filters as the Query Explorer. */
export function queryExportUrl(format: "csv" | "json", filters: QueryFilters): string {
  return apiUrl(`/queries/export${queryString({ format, ...filters })}`);
}

export const queries = {
  authStatus: () =>
    queryOptions({
      queryKey: ["auth-status"],
      queryFn: ({ signal }) => request<Schemas["AuthStatus"]>("GET", "/auth/status", { signal }),
      staleTime: 0,
    }),
  session: () =>
    queryOptions({
      queryKey: ["session"],
      queryFn: ({ signal }) => getData<Schemas["SessionInfo"]>("/auth/session", signal),
      staleTime: 60_000,
    }),
  overview: (hours: number) =>
    queryOptions({
      queryKey: ["overview", hours],
      queryFn: ({ signal }) => {
        const to = new Date();
        const from = new Date(to.getTime() - hours * 3_600_000);
        return timed("overview", () =>
          getData<Schemas["OverviewDto"]>(
            `/overview${queryString({ from: from.toISOString(), to: to.toISOString() })}`,
            signal,
          ),
        );
      },
      refetchInterval: pacedRefresh("overview"),
    }),
  queryLog: (filters: QueryFilters) =>
    infiniteQueryOptions({
      queryKey: ["queries", filters],
      queryFn: ({ pageParam, signal }) =>
        request<Schemas["QueryPageDto"]>(
          "GET",
          `/queries${queryString({ ...filters, cursor: pageParam, limit: 100 })}`,
          { signal },
        ),
      initialPageParam: undefined as string | undefined,
      getNextPageParam: (last) => last.page.next_cursor ?? undefined,
      gcTime: 0,
    }),
  rules: () =>
    queryOptions({
      queryKey: ["rules"],
      queryFn: ({ signal }) => getData<Rule[]>("/rules", signal),
      refetchInterval: REFRESH_MS,
    }),
  lists: () =>
    queryOptions({
      queryKey: ["lists"],
      queryFn: ({ signal }) => getData<List[]>("/lists", signal),
      refetchInterval: REFRESH_MS,
    }),
  blockedServices: () =>
    queryOptions({
      queryKey: ["blocked-services"],
      queryFn: ({ signal }) => getData<BlockedService[]>("/blocked-services", signal),
      refetchInterval: REFRESH_MS,
    }),
  clients: () =>
    queryOptions({
      queryKey: ["clients"],
      queryFn: ({ signal }) => timed("clients", () => getData<Client[]>("/clients", signal)),
      refetchInterval: pacedRefresh("clients"),
    }),
  groups: () =>
    queryOptions({
      queryKey: ["groups"],
      queryFn: ({ signal }) => getData<Group[]>("/groups", signal),
      refetchInterval: REFRESH_MS,
    }),
  fleetOverview: (hours: number) =>
    queryOptions({
      queryKey: ["fleet-overview", hours],
      queryFn: ({ signal }) =>
        timed("fleet-overview", () =>
          getData<Schemas["FleetOverviewDto"]>(`/fleet/overview${queryString({ hours })}`, signal),
        ),
      refetchInterval: pacedRefresh("fleet-overview"),
    }),
  sites: () =>
    queryOptions({
      queryKey: ["fleet-sites"],
      queryFn: ({ signal }) => timed("fleet-sites", () => getData<Site[]>("/fleet/sites", signal)),
      refetchInterval: pacedRefresh("fleet-sites"),
    }),
  fleetNodes: () =>
    queryOptions({
      queryKey: ["fleet-nodes"],
      queryFn: ({ signal }) => timed("fleet-nodes", () => getData<FleetNode[]>("/fleet/nodes", signal)),
      refetchInterval: pacedRefresh("fleet-nodes"),
    }),
  deployments: () =>
    queryOptions({
      queryKey: ["fleet-deployments"],
      queryFn: ({ signal }) =>
        timed("fleet-deployments", () => getData<Deployment[]>("/fleet/deployments", signal)),
      refetchInterval: pacedRefresh("fleet-deployments"),
    }),
  enrollmentTokens: () =>
    queryOptions({
      queryKey: ["fleet-tokens"],
      queryFn: ({ signal }) =>
        getData<Schemas["EnrollmentTokenDto"][]>("/fleet/enrollment-tokens", signal),
      refetchInterval: REFRESH_MS,
    }),
  blocking: () =>
    queryOptions({
      queryKey: ["blocking"],
      queryFn: ({ signal }) => getData<Schemas["BlockingDto"]>("/blocking", signal),
      refetchInterval: REFRESH_MS,
    }),
  devices: () =>
    queryOptions({
      queryKey: ["devices"],
      queryFn: ({ signal }) => timed("devices", () => getData<NetworkDevice[]>("/network/devices", signal)),
      refetchInterval: pacedRefresh("devices"),
    }),
  forwarders: () =>
    queryOptions({
      queryKey: ["forwarders"],
      queryFn: ({ signal }) => getData<ForwardZone[]>("/dns/forwarders", signal),
      refetchInterval: REFRESH_MS,
    }),
  upstreams: () =>
    queryOptions({
      queryKey: ["upstreams"],
      queryFn: ({ signal }) => getData<Schemas["UpstreamDto"][]>("/dns/upstreams", signal),
      refetchInterval: REFRESH_MS,
    }),
  cache: () =>
    queryOptions({
      queryKey: ["cache"],
      queryFn: ({ signal }) => getData<Schemas["CacheDto"]>("/dns/cache", signal),
      refetchInterval: REFRESH_MS,
    }),
  zones: () =>
    queryOptions({
      queryKey: ["zones"],
      queryFn: ({ signal }) => getData<LocalZone[]>("/dns/zones", signal),
      refetchInterval: REFRESH_MS,
    }),
  records: () =>
    queryOptions({
      queryKey: ["records"],
      queryFn: ({ signal }) => getData<LocalRecord[]>("/dns/records", signal),
      refetchInterval: REFRESH_MS,
    }),
  revisions: () =>
    queryOptions({
      queryKey: ["revisions"],
      queryFn: ({ signal }) => getData<Schemas["RevisionDto"][]>("/config/revisions", signal),
      refetchInterval: REFRESH_MS,
    }),
  nodeSettings: () =>
    queryOptions({
      queryKey: ["node-settings"],
      queryFn: ({ signal }) => getData<NodeSettingsView>("/node-settings", signal),
      refetchInterval: (query) => (query.state.data?.pending ? 1_000 : REFRESH_MS),
    }),
  settings: () =>
    queryOptions({
      queryKey: ["settings"],
      queryFn: ({ signal }) => getData<Settings>("/settings", signal),
      refetchInterval: REFRESH_MS,
    }),
  system: () =>
    queryOptions({
      queryKey: ["system"],
      queryFn: ({ signal }) => getData<Schemas["SystemStatus"]>("/system/status", signal),
      refetchInterval: REFRESH_MS,
    }),
  audit: () =>
    queryOptions({
      queryKey: ["audit"],
      queryFn: ({ signal }) => getData<Schemas["AuditEventDto"][]>("/audit-events", signal),
      refetchInterval: REFRESH_MS,
      gcTime: 0,
    }),
};

/** Every policy change can affect these, so they refresh together. */
const POLICY_KEYS = [
  "rules",
  "lists",
  "blocked-services",
  "clients",
  "groups",
  "zones",
  "records",
  "blocking",
  "devices",
  "forwarders",
  "cache",
  "revisions",
  "system",
  "settings",
  "audit",
  "fleet-overview",
  "fleet-sites",
  "fleet-nodes",
  "fleet-deployments",
  "fleet-tokens",
];

/**
 * A change to policy. On success it's already active on the node, because the API only returns
 * after publishing, so nothing here claims enforcement optimistically.
 */
export function usePolicyMutation<TVariables, TResult>(
  mutationFn: (variables: TVariables) => Promise<TResult>,
  successMessage?: string | ((result: TResult) => string),
) {
  const client = useQueryClient();
  return useMutation({
    mutationFn,
    onSuccess: (result) => {
      for (const key of POLICY_KEYS) void client.invalidateQueries({ queryKey: [key] });
      if (successMessage) {
        toast.success(typeof successMessage === "function" ? successMessage(result) : successMessage);
      }
    },
    onError: (error) => toast.error(errorMessage(error)),
  });
}

export const api = {
  createRule: (body: Schemas["CreateRule"]) => sendData<Rule>("POST", "/rules", { body }),
  updateRule: (rule: Rule, body: Schemas["UpdateRule"]) =>
    sendData<Rule>("PATCH", `/rules/${rule.id}`, { body, ifMatch: rule.revision }),
  deleteRule: (rule: Rule) =>
    request<void>("DELETE", `/rules/${rule.id}`, { ifMatch: rule.revision }),
  testRule: (body: Schemas["TestRuleRequest"]) => sendData<TestResult>("POST", "/rules/test", { body }),
  createList: (body: Schemas["CreateList"]) => sendData<List>("POST", "/lists", { body }),
  updateList: (id: string, body: Schemas["UpdateList"]) =>
    sendData<List>("PATCH", `/lists/${id}`, { body }),
  deleteList: (id: string) => request<void>("DELETE", `/lists/${id}`),
  refreshList: (id: string) => sendData<Schemas["JobDto"]>("POST", `/lists/${id}/refresh`),
  setBlockedService: (id: string, body: Schemas["SetBlockedService"]) =>
    sendData<BlockedService>("PUT", `/blocked-services/${encodeURIComponent(id)}`, { body }),
  diagnose: (body: Schemas["DiagnoseRequest"]) =>
    sendData<Schemas["DiagnosticReport"]>("POST", "/diagnostics/lookup", { body }),
  createClient: (body: Schemas["CreateClient"]) => sendData<Client>("POST", "/clients", { body }),
  updateClient: (id: string, body: Schemas["UpdateClient"]) =>
    sendData<Client>("PATCH", `/clients/${id}`, { body }),
  deleteClient: (id: string) => request<void>("DELETE", `/clients/${id}`),
  createGroup: (body: Schemas["CreateGroup"]) => sendData<Group>("POST", "/groups", { body }),
  updateGroup: (id: string, body: Schemas["UpdateGroup"]) =>
    sendData<Group>("PATCH", `/groups/${encodeURIComponent(id)}`, { body }),
  deleteGroup: (id: string) => request<void>("DELETE", `/groups/${encodeURIComponent(id)}`),
  createZone: (body: Schemas["CreateLocalZone"]) => sendData<LocalZone>("POST", "/dns/zones", { body }),
  deleteZone: (name: string) => request<void>("DELETE", `/dns/zones/${encodeURIComponent(name)}`),
  createRecord: (body: Schemas["CreateLocalRecord"]) =>
    sendData<LocalRecord>("POST", "/dns/records", { body }),
  updateRecord: (id: string, body: Schemas["UpdateLocalRecord"]) =>
    sendData<LocalRecord>("PATCH", `/dns/records/${id}`, { body }),
  deleteRecord: (id: string) => request<void>("DELETE", `/dns/records/${id}`),
  pauseBlocking: (body: Schemas["PauseBlocking"]) =>
    sendData<Schemas["BlockingDto"]>("POST", "/blocking/pause", { body }),
  resumeBlocking: () => sendData<Schemas["BlockingDto"]>("POST", "/blocking/resume"),
  createForwarder: (body: Schemas["CreateForwardZone"]) =>
    sendData<ForwardZone>("POST", "/dns/forwarders", { body }),
  updateForwarder: (id: string, body: Schemas["UpdateForwardZone"]) =>
    sendData<ForwardZone>("PATCH", `/dns/forwarders/${id}`, { body }),
  deleteForwarder: (id: string) => request<void>("DELETE", `/dns/forwarders/${id}`),
  flushCache: () => request<void>("DELETE", "/dns/cache"),
  testUpstreams: () => sendData<Schemas["UpstreamTestResult"]>("POST", "/dns/upstreams/test"),
  activateRevision: (revision: string) =>
    request<void>("POST", "/config/activate", { body: { revision } }),
  saveSettings: (body: Settings) => sendData<Settings>("PUT", "/settings", { body }),
  nodeSettings: () => getData<NodeSettingsView>("/node-settings"),
  saveNodeSettings: (body: NodeSettings) =>
    sendData<Schemas["SaveNodeSettingsResponse"]>("PUT", "/node-settings", { body }),
  keepNodeSettings: () => sendData<NodeSettingsView>("POST", "/node-settings/confirm"),
  undoNodeSettings: () => sendData<NodeSettingsView>("POST", "/node-settings/undo"),
  createSite: (body: Schemas["CreateSite"]) => sendData<Site>("POST", "/fleet/sites", { body }),
  updateSite: (id: string, body: Schemas["UpdateSite"]) =>
    sendData<Site>("PATCH", `/fleet/sites/${id}`, { body }),
  deleteSite: (id: string) => request<void>("DELETE", `/fleet/sites/${id}`),
  renameNode: (id: string, body: Schemas["UpdateNode"]) =>
    request<void>("PATCH", `/fleet/nodes/${id}`, { body }),
  removeNode: (id: string) => request<void>("DELETE", `/fleet/nodes/${id}`),
  createEnrollmentToken: (body: Schemas["CreateEnrollmentToken"]) =>
    sendData<Schemas["EnrollmentTokenCreated"]>("POST", "/fleet/enrollment-tokens", { body }),
  deleteEnrollmentToken: (id: string) => request<void>("DELETE", `/fleet/enrollment-tokens/${id}`),
  deploy: (body: Schemas["CreateDeployment"]) =>
    sendData<Deployment>("POST", "/fleet/deployments", { body }),
  promoteDeployment: (id: string) => sendData<Deployment>("POST", `/fleet/deployments/${id}/promote`),
  rollbackDeployment: (id: string) =>
    sendData<Deployment>("POST", `/fleet/deployments/${id}/rollback`, { body: {} }),
  login: (body: Schemas["LoginRequest"]) =>
    sendData<Schemas["SessionInfo"]>("POST", "/auth/login", { body }),
  setup: (body: Schemas["SetupRequest"]) =>
    sendData<Schemas["SessionInfo"]>("POST", "/auth/setup", { body }),
  logout: () => request<void>("POST", "/auth/logout"),
  changePassword: (body: Schemas["ChangePasswordRequest"]) =>
    request<void>("POST", "/auth/password", { body }),
};
