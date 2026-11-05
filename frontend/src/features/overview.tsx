import { useQuery } from "@tanstack/react-query";
import { format } from "date-fns";
import { useState } from "react";
import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import { ErrorState, Loading, PageHeader } from "@/components/states";
import { Button } from "@/components/ui/button";
import { Card, CardHeader } from "@/components/ui/card";
import { Select } from "@/components/ui/form";
import { Table, TableWrap, Td, Th } from "@/components/ui/table";
import { type Schemas } from "@/lib/api/client";
import { queries } from "@/lib/api/hooks";
import { formatCount, formatDuration } from "@/lib/format";

const RANGES = [
  { hours: 1, label: "Last hour" },
  { hours: 24, label: "Last 24 hours" },
  { hours: 24 * 7, label: "Last 7 days" },
];

const SERIES = [
  { key: "forwarded", label: "Answered", color: "var(--series-forwarded)" },
  { key: "blocked", label: "Blocked", color: "var(--series-blocked)" },
  { key: "failed", label: "Failed", color: "var(--series-failed)" },
] as const;

function Stat({ label, value, detail }: { label: string; value: string; detail?: string }) {
  return (
    <Card className="p-4">
      <p className="text-xs font-medium text-text-muted">{label}</p>
      <p className="mt-1 text-2xl font-semibold">{value}</p>
      {detail && <p className="mt-0.5 text-xs text-text-muted">{detail}</p>}
    </Card>
  );
}

function TopList({
  title,
  description,
  items,
  empty,
}: {
  title: string;
  description: string;
  items: Schemas["CountDto"][];
  empty: string;
}) {
  const largest = items[0]?.count ?? 1;
  return (
    <Card>
      <CardHeader title={title} description={description} />
      {items.length === 0 ? (
        <p className="px-4 pb-4 text-sm text-text-muted">{empty}</p>
      ) : (
        <ol className="space-y-2.5 px-4 pb-4">
          {items.map((item) => (
            <li key={item.name} className="text-sm">
              <div className="flex items-baseline justify-between gap-3">
                <span className="truncate" title={item.name}>
                  {item.name}
                </span>
                <span className="shrink-0 text-text-secondary">{formatCount(item.count)}</span>
              </div>
              <div className="mt-1 h-1 rounded-full bg-surface-muted">
                <div
                  className="h-1 rounded-full bg-text-muted"
                  style={{ width: `${Math.max(2, (item.count / largest) * 100)}%` }}
                />
              </div>
            </li>
          ))}
        </ol>
      )}
    </Card>
  );
}

interface TooltipEntry {
  dataKey?: unknown;
  value?: unknown;
}

function ChartTooltip({
  active,
  label,
  payload,
  bucketSeconds,
}: {
  active?: boolean;
  label?: unknown;
  payload?: readonly TooltipEntry[];
  bucketSeconds: number;
}) {
  if (!active || !payload?.length || typeof label !== "string") return null;
  return (
    <div className="rounded-md border border-border bg-surface px-3 py-2 text-xs shadow-md">
      <p className="font-medium">{format(new Date(label), "MMM d, HH:mm")}</p>
      <p className="mb-1.5 text-text-muted">Per {Math.round(bucketSeconds / 60)} minutes</p>
      {SERIES.map((series) => {
        const entry = payload.find((item) => item.dataKey === series.key);
        return (
          <p key={series.key} className="flex items-center justify-between gap-4">
            <span className="flex items-center gap-1.5 text-text-secondary">
              <span className="size-2 rounded-full" style={{ background: series.color }} />
              {series.label}
            </span>
            <span className="font-medium">{formatCount(Number(entry?.value ?? 0))}</span>
          </p>
        );
      })}
    </div>
  );
}

export type TrafficData = Pick<
  Schemas["OverviewDto"],
  "buckets" | "bucket_seconds" | "forwarded" | "blocked" | "failed"
>;

export function TrafficChart({ data }: { data: TrafficData }) {
  const [showTable, setShowTable] = useState(false);
  const longRange = data.bucket_seconds >= 3600;
  const tickFormat = (value: string) => format(new Date(value), longRange ? "MMM d" : "HH:mm");
  const active = data.buckets.filter((bucket) => bucket.forwarded + bucket.blocked + bucket.failed > 0);

  return (
    <Card>
      <CardHeader
        title="Query traffic"
        description={`Queries per ${Math.round(data.bucket_seconds / 60)} minutes`}
        actions={
          <Button size="sm" onClick={() => setShowTable((value) => !value)} aria-pressed={showTable}>
            {showTable ? "Show chart" : "Show table"}
          </Button>
        }
      />
      {showTable ? (
        <TableWrap className="max-h-72 overflow-y-auto">
          <Table>
            <thead>
              <tr>
                <Th>Time</Th>
                {SERIES.map((series) => (
                  <Th key={series.key} className="text-right">
                    {series.label}
                  </Th>
                ))}
              </tr>
            </thead>
            <tbody>
              {active.map((bucket) => (
                <tr key={bucket.start}>
                  <Td>{format(new Date(bucket.start), "MMM d, HH:mm")}</Td>
                  {SERIES.map((series) => (
                    <Td key={series.key} className="text-right">
                      {formatCount(bucket[series.key])}
                    </Td>
                  ))}
                </tr>
              ))}
            </tbody>
          </Table>
          {active.length === 0 && (
            <p className="px-4 py-6 text-center text-sm text-text-muted">No queries in this range.</p>
          )}
        </TableWrap>
      ) : (
        <>
          <ul className="flex flex-wrap gap-x-4 gap-y-1 px-4 pb-2" aria-label="Chart legend">
            {SERIES.map((series) => (
              <li key={series.key} className="flex items-center gap-1.5 text-xs text-text-secondary">
                <span className="h-0.5 w-3 rounded-full" style={{ background: series.color }} />
                {series.label}
              </li>
            ))}
          </ul>
          <div
            className="h-64 px-2 pb-2"
            role="img"
            aria-label={`Line chart of queries over time: ${formatCount(data.forwarded)} forwarded, ${formatCount(data.blocked)} blocked and ${formatCount(data.failed)} failed. Use Show table for the values.`}
          >
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={data.buckets} margin={{ top: 8, right: 12, left: 0, bottom: 0 }}>
                <CartesianGrid stroke="var(--grid)" vertical={false} />
                <XAxis
                  dataKey="start"
                  tickFormatter={tickFormat}
                  tick={{ fontSize: 11, fill: "var(--text-muted)" }}
                  tickLine={false}
                  axisLine={{ stroke: "var(--border)" }}
                  minTickGap={48}
                />
                <YAxis
                  allowDecimals={false}
                  tick={{ fontSize: 11, fill: "var(--text-muted)" }}
                  tickLine={false}
                  axisLine={false}
                  width={44}
                />
                <Tooltip
                  cursor={{ stroke: "var(--border-strong)" }}
                  content={(props) => (
                    <ChartTooltip
                      active={props.active}
                      label={props.label}
                      payload={props.payload as readonly TooltipEntry[] | undefined}
                      bucketSeconds={data.bucket_seconds}
                    />
                  )}
                />
                {SERIES.map((series) => (
                  <Line
                    key={series.key}
                    type="monotone"
                    dataKey={series.key}
                    name={series.label}
                    stroke={series.color}
                    strokeWidth={2}
                    dot={false}
                    activeDot={{ r: 4, stroke: "var(--surface)", strokeWidth: 2 }}
                    isAnimationActive={false}
                  />
                ))}
              </LineChart>
            </ResponsiveContainer>
          </div>
        </>
      )}
    </Card>
  );
}

export function OverviewPage() {
  const [hours, setHours] = useState(24);
  const overview = useQuery(queries.overview(hours));
  const data = overview.data;
  const blockedShare = data && data.total > 0 ? (data.blocked / data.total) * 100 : 0;
  const rangeLabel = RANGES.find((range) => range.hours === hours)?.label.toLowerCase() ?? "";

  return (
    <>
      <PageHeader
        title="Overview"
        description={
          overview.dataUpdatedAt
            ? `Last updated ${format(overview.dataUpdatedAt, "HH:mm:ss")}${overview.isRefetchError ? " · refresh failed, showing older data" : ""}`
            : undefined
        }
        actions={
          <div className="w-40">
            <label htmlFor="overview-range" className="sr-only">
              Time range
            </label>
            <Select
              id="overview-range"
              value={hours}
              onChange={(event) => setHours(Number(event.target.value))}
            >
              {RANGES.map((range) => (
                <option key={range.hours} value={range.hours}>
                  {range.label}
                </option>
              ))}
            </Select>
          </div>
        }
      />
      {overview.isPending && <Loading />}
      {overview.isError && !data && (
        <ErrorState error={overview.error} onRetry={() => void overview.refetch()} />
      )}
      {data && (
        <div className="space-y-4">
          {data.query_log_mode !== "full" && (
            <p className="rounded-lg border border-border bg-surface-muted px-3 py-2 text-sm text-text-secondary">
              Query logging is set to {data.query_log_mode.replace("_", " ")}, so some details below
              aren&apos;t recorded. You can change this in Settings.
            </p>
          )}
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
            <Stat
              label="Total queries"
              value={formatCount(data.total)}
              detail={`${formatCount(data.cached)} from cache, ${formatCount(data.local)} local`}
            />
            <Stat
              label="Blocked"
              value={formatCount(data.blocked)}
              detail={`${blockedShare.toFixed(1)}% of queries`}
            />
            <Stat
              label="Failed or rejected"
              value={formatCount(data.failed + data.rejected)}
              detail={`${formatCount(data.failed)} failed, ${formatCount(data.rejected)} rejected`}
            />
            <Stat
              label="Average response time"
              value={formatDuration(data.average_latency_us)}
              detail="Includes upstream time"
            />
          </div>
          <TrafficChart data={data} />
          <div className="grid gap-4 lg:grid-cols-3">
            <TopList
              title="Top clients"
              description={`By queries, ${rangeLabel}`}
              items={data.top_clients}
              empty="No client data in this range."
            />
            <TopList
              title="Top blocked domains"
              description="From recent query history"
              items={data.top_blocked_domains}
              empty="Nothing blocked in this range."
            />
            <TopList
              title="Top allowed domains"
              description="From recent query history"
              items={data.top_domains}
              empty="No queries in this range."
            />
          </div>
        </div>
      )}
    </>
  );
}
