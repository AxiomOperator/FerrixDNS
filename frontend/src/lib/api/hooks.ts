import {
  infiniteQueryOptions,
  queryOptions,
  useMutation,
  useQueryClient,
} from "@tanstack/react-query";
import { toast } from "sonner";

import { type Schemas, errorMessage, getData, request, sendData } from "./client";

export type Rule = Schemas["RuleDto"];
export type List = Schemas["ListDto"];
export type Client = Schemas["ClientDto"];
export type Group = Schemas["GroupDto"];
export type QueryEvent = Schemas["QueryEventDto"];
export type Settings = Schemas["SettingsDto"];
export type TestResult = Schemas["TestRuleResponse"];
export type LocalZone = Schemas["LocalZoneDto"];
export type LocalRecord = Schemas["LocalRecordDto"];

export interface QueryFilters {
  qname?: string;
  client?: string;
  action?: string;
  qtype?: string;
}

const REFRESH_MS = 15_000;

function queryString(values: Record<string, string | number | undefined>): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(values)) {
    if (value !== undefined && value !== "") params.set(key, String(value));
  }
  const text = params.toString();
  return text ? `?${text}` : "";
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
        return getData<Schemas["OverviewDto"]>(
          `/overview${queryString({ from: from.toISOString(), to: to.toISOString() })}`,
          signal,
        );
      },
      refetchInterval: REFRESH_MS,
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
    }),
  lists: () =>
    queryOptions({
      queryKey: ["lists"],
      queryFn: ({ signal }) => getData<List[]>("/lists", signal),
      // Downloads finish in the background, so this keeps their status current.
      refetchInterval: 3_000,
    }),
  clients: () =>
    queryOptions({
      queryKey: ["clients"],
      queryFn: ({ signal }) => getData<Client[]>("/clients", signal),
      refetchInterval: REFRESH_MS,
    }),
  groups: () =>
    queryOptions({
      queryKey: ["groups"],
      queryFn: ({ signal }) => getData<Group[]>("/groups", signal),
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
    }),
  records: () =>
    queryOptions({
      queryKey: ["records"],
      queryFn: ({ signal }) => getData<LocalRecord[]>("/dns/records", signal),
    }),
  revisions: () =>
    queryOptions({
      queryKey: ["revisions"],
      queryFn: ({ signal }) => getData<Schemas["RevisionDto"][]>("/config/revisions", signal),
    }),
  settings: () =>
    queryOptions({
      queryKey: ["settings"],
      queryFn: ({ signal }) => getData<Settings>("/settings", signal),
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
      gcTime: 0,
    }),
};

/** Every policy change can affect these, so they refresh together. */
const POLICY_KEYS = [
  "rules",
  "lists",
  "clients",
  "groups",
  "zones",
  "records",
  "cache",
  "revisions",
  "system",
  "settings",
  "audit",
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
  flushCache: () => request<void>("DELETE", "/dns/cache"),
  testUpstreams: () => sendData<Schemas["UpstreamTestResult"]>("POST", "/dns/upstreams/test"),
  activateRevision: (revision: string) =>
    request<void>("POST", "/config/activate", { body: { revision } }),
  saveSettings: (body: Settings) => sendData<Settings>("PUT", "/settings", { body }),
  login: (body: Schemas["LoginRequest"]) =>
    sendData<Schemas["SessionInfo"]>("POST", "/auth/login", { body }),
  setup: (body: Schemas["SetupRequest"]) =>
    sendData<Schemas["SessionInfo"]>("POST", "/auth/setup", { body }),
  logout: () => request<void>("POST", "/auth/logout"),
  changePassword: (body: Schemas["ChangePasswordRequest"]) =>
    request<void>("POST", "/auth/password", { body }),
};
