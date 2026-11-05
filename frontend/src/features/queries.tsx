import { useInfiniteQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useSearch } from "@tanstack/react-router";
import {
  type ColumnDef,
  flexRender,
  getCoreRowModel,
  useReactTable,
} from "@tanstack/react-table";
import { useVirtualizer } from "@tanstack/react-virtual";
import { addHours, format } from "date-fns";
import { type ReactNode, useEffect, useMemo, useRef, useState } from "react";
import { toast } from "sonner";

import { ErrorState, Loading, PageHeader } from "@/components/states";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Dialog } from "@/components/ui/dialog";
import { Field, Input, Select } from "@/components/ui/form";
import { Switch } from "@/components/ui/switch";
import { apiUrl, errorMessage } from "@/lib/api/client";
import { type QueryEvent, type QueryFilters, api, queries, queryExportUrl } from "@/lib/api/hooks";
import { formatDuration, formatTime, shortRevision } from "@/lib/format";

const ROW_HEIGHT = 41;
const MAX_LIVE_EVENTS = 500;

function ResultBadge({ event }: { event: QueryEvent }) {
  switch (event.decision.action) {
    case "blocked":
      return <Badge tone="danger">Blocked</Badge>;
    case "forwarded":
      return <Badge tone="success">Forwarded</Badge>;
    case "cached":
      return <Badge tone="success">Cached</Badge>;
    case "stale":
      return <Badge tone="warning">Expired answer</Badge>;
    case "local":
      return <Badge tone="success">Local</Badge>;
    case "rejected":
      return <Badge tone="warning">Rejected</Badge>;
    case "rate_limited":
      return <Badge tone="warning">Rate limited</Badge>;
    default:
      return <Badge tone="error">Failed</Badge>;
  }
}

function clientLabel(event: QueryEvent): string {
  return event.client.id ?? event.client.address ?? "Not recorded";
}

function matchesFilters(event: QueryEvent, filters: QueryFilters): boolean {
  if (filters.action && event.decision.action !== filters.action) return false;
  if (filters.qtype && event.question.type !== filters.qtype.toUpperCase()) return false;
  if (filters.qname && !event.question.name?.includes(filters.qname.toLowerCase())) return false;
  if (filters.client && filters.client !== event.client.id && filters.client !== event.client.address) {
    return false;
  }
  return true;
}

const columns: ColumnDef<QueryEvent>[] = [
  {
    id: "time",
    header: "Time",
    cell: ({ row }) => <span className="text-text-secondary">{formatTime(row.original.occurred_at)}</span>,
    meta: { width: "w-36 shrink-0" },
  },
  {
    id: "result",
    header: "Result",
    cell: ({ row }) => <ResultBadge event={row.original} />,
    meta: { width: "w-28 shrink-0" },
  },
  {
    id: "domain",
    header: "Domain",
    cell: ({ row }) => (
      <span className="block truncate font-medium" title={row.original.question.name ?? undefined}>
        {row.original.question.name ?? "Not recorded"}
      </span>
    ),
    meta: { width: "min-w-48 flex-1" },
  },
  {
    id: "type",
    header: "Type",
    cell: ({ row }) => row.original.question.type,
    meta: { width: "w-16 shrink-0" },
  },
  {
    id: "client",
    header: "Client",
    cell: ({ row }) => (
      <span className="block truncate" title={clientLabel(row.original)}>
        {clientLabel(row.original)}
      </span>
    ),
    meta: { width: "w-40 shrink-0" },
  },
  {
    id: "duration",
    header: "Time taken",
    cell: ({ row }) => <span className="text-text-secondary">{formatDuration(row.original.duration_us)}</span>,
    meta: { width: "w-24 shrink-0" },
  },
];

function columnWidth(meta: unknown): string {
  return (meta as { width?: string } | undefined)?.width ?? "";
}

function explanation(event: QueryEvent): string {
  const { decision } = event;
  switch (decision.action) {
    case "forwarded":
      return event.upstream
        ? `No rule blocked this, so it was answered by ${event.upstream}.`
        : "No rule blocked this, so it was answered upstream.";
    case "cached":
      return "No rule blocked this, and it was answered from the cache. Current rules are checked on every cached answer.";
    case "stale":
      return "No rule blocked this. The upstream servers couldn't answer, so this node used its last known answer, which had expired. Current rules are still checked on it.";
    case "local":
      return "This node answered itself, from a local zone or a name reserved for local use. It wasn't sent upstream.";
    case "rejected":
      return "This node doesn't serve this kind of request, so it was refused without being forwarded.";
    case "rate_limited":
      return "This device went over its query limit, so this node refused its queries until it slowed down. Only the first refused query each minute is recorded. The limit is under Settings.";
    case "failed":
      return "No usable answer could be produced. The upstream servers may be unreachable or returned an error.";
    default: {
      const target =
        decision.matched_name && decision.matched_name !== event.question.name
          ? ` The answer pointed to ${decision.matched_name} through a CNAME, and that name is blocked.`
          : "";
      if (decision.source === "rule") {
        return `Blocked by a rule${decision.rule_pattern ? ` for ${decision.rule_pattern}` : ""}.${target}`;
      }
      return `Blocked by the list ${decision.list_name ?? decision.list_id ?? ""}.${target}`;
    }
  }
}

function Detail({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex justify-between gap-4 border-b border-border py-2 text-sm">
      <dt className="shrink-0 text-text-muted">{label}</dt>
      <dd className="min-w-0 text-right break-words">{children}</dd>
    </div>
  );
}

function ExceptionForm({
  event,
  onDone,
  readOnly,
}: {
  event: QueryEvent;
  onDone: () => void;
  readOnly: boolean;
}) {
  const client = useQueryClient();
  const domain = event.decision.matched_name ?? event.question.name ?? "";
  const [reason, setReason] = useState("");
  const [hours, setHours] = useState(24);

  const exception = useMutation({
    mutationFn: () =>
      api.createRule({
        action: "allow",
        match_type: "exact",
        pattern: domain,
        scope: { kind: "global" },
        reason: reason || "Exception from the query log",
        expires_at: hours > 0 ? addHours(new Date(), hours).toISOString() : undefined,
      }),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ["rules"] });
      toast.success(`${domain} is now allowed on this node`);
      onDone();
    },
    onError: (error) => toast.error(errorMessage(error)),
  });

  return (
    <form
      className="mt-4 space-y-3 rounded-md bg-surface-muted p-3"
      onSubmit={(submitted) => {
        submitted.preventDefault();
        exception.mutate();
      }}
    >
      <p className="text-sm font-medium">Allow {domain}</p>
      <Field label="Reason" htmlFor="exception-reason">
        <Input
          id="exception-reason"
          value={reason}
          placeholder="Why this is needed"
          onChange={(changed) => setReason(changed.target.value)}
        />
      </Field>
      <Field label="Allow for" htmlFor="exception-expiry">
        <Select
          id="exception-expiry"
          value={hours}
          onChange={(changed) => setHours(Number(changed.target.value))}
        >
          <option value={1}>1 hour</option>
          <option value={24}>24 hours</option>
          <option value={168}>7 days</option>
          <option value={0}>Until removed</option>
        </Select>
      </Field>
      <p className="text-xs text-text-secondary">
        This takes effect right away on this node. Devices can keep a cached block for up to its TTL.
      </p>
      <Button type="submit" variant="primary" size="sm" disabled={exception.isPending || readOnly}>
        Allow domain
      </Button>
    </form>
  );
}

function EventDrawer({
  event,
  onClose,
  readOnly,
}: {
  event: QueryEvent | undefined;
  onClose: () => void;
  readOnly: boolean;
}) {
  return (
    <Dialog
      side
      open={event !== undefined}
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
      title={event?.question.name ?? "Query"}
      description={event ? format(new Date(event.occurred_at), "MMM d, yyyy HH:mm:ss") : undefined}
    >
      {event && (
        <>
          <div className="mb-3 flex items-center gap-2">
            <ResultBadge event={event} />
            <span className="text-sm text-text-secondary">{event.rcode}</span>
          </div>
          <h3 className="text-sm font-semibold">Why this happened</h3>
          <p className="mt-1 mb-3 text-sm text-text-secondary">{explanation(event)}</p>
          <dl>
            <Detail label="Type">{event.question.type}</Detail>
            <Detail label="Client">{clientLabel(event)}</Detail>
            {event.client.id && event.client.address && <Detail label="Address">{event.client.address}</Detail>}
            <Detail label="Time taken">{formatDuration(event.duration_us)}</Detail>
            {event.upstream && <Detail label="Upstream">{event.upstream}</Detail>}
            {event.decision.matched_name && <Detail label="Matched name">{event.decision.matched_name}</Detail>}
            {event.revision_id && <Detail label="Policy revision">{shortRevision(event.revision_id)}</Detail>}
          </dl>
          <Link
            to="/diagnostics"
            search={{
              name: event.question.name ?? undefined,
              type: event.question.type,
              client: event.client.address ?? undefined,
            }}
            className="mt-3 inline-block text-sm font-medium text-accent underline underline-offset-2"
          >
            Diagnose this query
          </Link>
          {event.decision.action === "blocked" && (
            <ExceptionForm key={event.occurred_at} event={event} onDone={onClose} readOnly={readOnly} />
          )}
        </>
      )}
    </Dialog>
  );
}

export function QueriesPage({ readOnly }: { readOnly: boolean }) {
  const filters = useSearch({ from: "/_authenticated/queries" });
  const navigate = useNavigate({ from: "/queries" });
  const [selected, setSelected] = useState<QueryEvent>();
  const [live, setLive] = useState(true);
  const [liveEvents, setLiveEvents] = useState<QueryEvent[]>([]);
  const [search, setSearch] = useState(filters.qname ?? "");

  const log = useInfiniteQuery(queries.queryLog(filters));
  const { refetch: refetchLog } = log;

  function setFilter(next: QueryFilters) {
    void navigate({ search: (previous) => ({ ...previous, ...next }) as never });
  }

  // Keep the URL shareable without a request on every keystroke.
  useEffect(() => {
    const timer = setTimeout(() => {
      if (search !== (filters.qname ?? "")) setFilter({ qname: search || undefined });
    }, 300);
    return () => clearTimeout(timer);
    // Only typing should restart this timer.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [search]);

  useEffect(() => {
    setLiveEvents([]);
    if (!live) return;
    const source = new EventSource(apiUrl("/queries/stream"));
    // Queries answered while the stream was off, or reconnecting after a restart, were never sent.
    source.addEventListener("open", () => void refetchLog());
    source.addEventListener("query", (message) => {
      const event = JSON.parse((message as MessageEvent<string>).data) as QueryEvent;
      if (matchesFilters(event, filters)) {
        setLiveEvents((current) => [event, ...current].slice(0, MAX_LIVE_EVENTS));
      }
    });
    return () => source.close();
  }, [live, filters, refetchLog]);

  const events = useMemo(() => {
    const stored = log.data?.pages.flatMap((page) => page.data) ?? [];
    // Events that arrived before the first page loaded can also be in it.
    const newest = stored[0]?.occurred_at ?? "";
    const fresh = liveEvents.filter((event) => event.occurred_at > newest);
    return [...fresh, ...stored];
  }, [log.data, liveEvents]);

  const table = useReactTable({ data: events, columns, getCoreRowModel: getCoreRowModel() });
  const rows = table.getRowModel().rows;
  const scroller = useRef<HTMLDivElement>(null);
  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scroller.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 12,
  });

  const items = virtualizer.getVirtualItems();
  const lastIndex = items[items.length - 1]?.index ?? 0;
  const { hasNextPage, isFetchingNextPage, fetchNextPage } = log;
  useEffect(() => {
    if (lastIndex >= rows.length - 20 && hasNextPage && !isFetchingNextPage) {
      void fetchNextPage();
    }
  }, [lastIndex, rows.length, hasNextPage, isFetchingNextPage, fetchNextPage]);

  const hasFilters = Boolean(filters.qname || filters.client || filters.action || filters.qtype);

  return (
    <>
      <PageHeader
        title="Query Explorer"
        description="See each query, and why it was allowed or blocked."
        actions={
          <div className="flex flex-wrap items-center gap-3 text-sm text-text-secondary">
            <span className="flex items-center gap-2">
              <Switch checked={live} onCheckedChange={setLive} label="Live updates" />
              Live updates
            </span>
            <a
              href={queryExportUrl("csv", filters)}
              download
              className="inline-flex h-8 items-center rounded-md border border-border-strong bg-surface px-2.5 text-xs font-medium text-text hover:bg-surface-muted"
            >
              Export CSV
            </a>
            <a
              href={queryExportUrl("json", filters)}
              download
              className="inline-flex h-8 items-center rounded-md border border-border-strong bg-surface px-2.5 text-xs font-medium text-text hover:bg-surface-muted"
            >
              Export JSON
            </a>
          </div>
        }
      />
      <div className="mb-3 grid grid-cols-2 gap-2 md:grid-cols-4">
        <div className="col-span-2 md:col-span-1">
          <label htmlFor="filter-domain" className="sr-only">
            Domain contains
          </label>
          <Input
            id="filter-domain"
            placeholder="Domain contains…"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
          />
        </div>
        <div>
          <label htmlFor="filter-result" className="sr-only">
            Result
          </label>
          <Select
            id="filter-result"
            value={filters.action ?? ""}
            onChange={(event) => setFilter({ action: event.target.value || undefined })}
          >
            <option value="">All results</option>
            <option value="blocked">Blocked</option>
            <option value="forwarded">Forwarded</option>
            <option value="cached">Cached</option>
            <option value="stale">Expired answer</option>
            <option value="local">Local</option>
            <option value="failed">Failed</option>
            <option value="rejected">Rejected</option>
            <option value="rate_limited">Rate limited</option>
          </Select>
        </div>
        <div>
          <label htmlFor="filter-type" className="sr-only">
            Record type
          </label>
          <Select
            id="filter-type"
            value={filters.qtype ?? ""}
            onChange={(event) => setFilter({ qtype: event.target.value || undefined })}
          >
            <option value="">All types</option>
            {["A", "AAAA", "CNAME", "HTTPS", "MX", "NS", "PTR", "SRV", "SVCB", "TXT"].map((type) => (
              <option key={type} value={type}>
                {type}
              </option>
            ))}
          </Select>
        </div>
        <div className="col-span-2 md:col-span-1">
          <label htmlFor="filter-client" className="sr-only">
            Client
          </label>
          <Input
            id="filter-client"
            placeholder="Client ID or address"
            defaultValue={filters.client ?? ""}
            onBlur={(event) => setFilter({ client: event.target.value.trim() || undefined })}
            onKeyDown={(event) => {
              if (event.key === "Enter") {
                setFilter({ client: event.currentTarget.value.trim() || undefined });
              }
            }}
          />
        </div>
      </div>

      <Card className="overflow-hidden">
        {log.isPending && <Loading />}
        {log.isError && <ErrorState error={log.error} onRetry={() => void log.refetch()} />}
        {log.isSuccess && rows.length === 0 && (
          <div className="px-4 py-10 text-center">
            <p className="text-sm font-medium">{hasFilters ? "No matching queries" : "No queries yet"}</p>
            <p className="mt-1 text-sm text-text-muted">
              {hasFilters
                ? "Try removing a filter."
                : "Point a device's DNS at this node, and its queries will appear here."}
            </p>
          </div>
        )}
        {log.isSuccess && rows.length > 0 && (
          <div
            ref={scroller}
            className="h-[calc(100dvh-16rem)] min-h-80 overflow-auto"
            role="region"
            aria-label="Query log"
            tabIndex={0}
          >
            <div className="min-w-[760px]">
              {table.getHeaderGroups().map((group) => (
                <div
                  key={group.id}
                  className="sticky top-0 z-10 flex border-b border-border bg-surface px-2 text-xs font-medium text-text-muted"
                >
                  {group.headers.map((header) => (
                    <div
                      key={header.id}
                      className={`px-2 py-2 ${columnWidth(header.column.columnDef.meta)}`}
                    >
                      {flexRender(header.column.columnDef.header, header.getContext())}
                    </div>
                  ))}
                </div>
              ))}
              <div style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
                {items.map((item) => {
                  const row = rows[item.index];
                  if (!row) return null;
                  return (
                    <button
                      type="button"
                      key={row.id}
                      onClick={() => setSelected(row.original)}
                      className="absolute left-0 flex w-full cursor-pointer items-center border-b border-border px-2 text-left text-sm hover:bg-surface-muted"
                      style={{ height: item.size, top: item.start }}
                    >
                      {row.getVisibleCells().map((cell) => (
                        <div
                          key={cell.id}
                          className={`min-w-0 px-2 ${columnWidth(cell.column.columnDef.meta)}`}
                        >
                          {flexRender(cell.column.columnDef.cell, cell.getContext())}
                        </div>
                      ))}
                    </button>
                  );
                })}
              </div>
            </div>
          </div>
        )}
      </Card>
      <EventDrawer event={selected} onClose={() => setSelected(undefined)} readOnly={readOnly} />
    </>
  );
}
