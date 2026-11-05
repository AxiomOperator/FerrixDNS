import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useState } from "react";

import { ErrorState, Loading, PageHeader } from "@/components/states";
import { Card, CardHeader } from "@/components/ui/card";
import { Select } from "@/components/ui/form";
import { Table, TableWrap, Td, Th } from "@/components/ui/table";
import { TrafficChart, type TrafficData } from "@/features/overview";
import { type Schemas } from "@/lib/api/client";
import { queries } from "@/lib/api/hooks";
import { formatCount, formatDuration } from "@/lib/format";

const RANGES = [
  { hours: 1, label: "Last hour" },
  { hours: 24, label: "Last 24 hours" },
  { hours: 24 * 7, label: "Last 7 days" },
];

function Stat({ label, value, detail }: { label: string; value: string; detail?: string }) {
  return (
    <Card className="p-4">
      <p className="text-xs font-medium text-text-muted">{label}</p>
      <p className="mt-1 text-2xl font-semibold">{value}</p>
      {detail && <p className="mt-0.5 text-xs text-text-muted">{detail}</p>}
    </Card>
  );
}

function trafficData(data: Schemas["FleetOverviewDto"]): TrafficData {
  return {
    bucket_seconds: data.bucket_seconds,
    forwarded: data.answered,
    blocked: data.blocked,
    failed: data.failed,
    buckets: data.buckets.map((bucket) => ({
      start: bucket.start,
      forwarded: bucket.answered,
      blocked: bucket.blocked,
      failed: bucket.failed,
    })) as TrafficData["buckets"],
  };
}

export function FleetOverviewPage() {
  const [hours, setHours] = useState(1);
  const overview = useQuery(queries.fleetOverview(hours));
  const data = overview.data;
  const offline = data ? data.node_count - data.nodes_online : 0;

  return (
    <>
      <PageHeader
        title="Fleet overview"
        description="Query counts and health from every node. Query names and device addresses stay on each node."
        actions={
          <div className="w-40">
            <label htmlFor="fleet-range" className="sr-only">
              Time range
            </label>
            <Select id="fleet-range" value={hours} onChange={(event) => setHours(Number(event.target.value))}>
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
      {overview.isError && !data && <ErrorState error={overview.error} onRetry={() => void overview.refetch()} />}
      {data && (
        <div className="space-y-4">
          {data.site_count === 0 && (
            <p className="rounded-lg border border-border bg-surface-muted px-3 py-2 text-sm">
              Nothing is set up yet.{" "}
              <Link to="/fleet/sites" className="font-medium text-accent underline underline-offset-2">
                Add a site
              </Link>{" "}
              to get started.
            </p>
          )}
          {offline > 0 && (
            <p role="status" className="rounded-lg border border-border bg-warning-soft px-3 py-2 text-sm text-warning">
              {offline === 1 ? "1 node isn't" : `${offline} nodes aren't`} reporting in. They keep serving
              DNS with their last policy, if they're still running.{" "}
              <Link to="/fleet/nodes" className="font-medium underline underline-offset-2">
                See nodes
              </Link>
            </p>
          )}
          {data.sites_with_undeployed_changes > 0 && (
            <p className="rounded-lg border border-border bg-surface-muted px-3 py-2 text-sm">
              {data.sites_with_undeployed_changes === 1
                ? "1 site has changes"
                : `${data.sites_with_undeployed_changes} sites have changes`}{" "}
              that haven't been deployed.{" "}
              <Link to="/fleet/sites" className="font-medium text-accent underline underline-offset-2">
                See sites
              </Link>
            </p>
          )}
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
            <Stat
              label="Nodes online"
              value={`${formatCount(data.nodes_online)} of ${formatCount(data.node_count)}`}
              detail={`In ${formatCount(data.site_count)} ${data.site_count === 1 ? "site" : "sites"}`}
            />
            <Stat
              label="Total queries"
              value={formatCount(data.total)}
              detail={`${formatCount(data.cached)} from cache, ${formatCount(data.stale)} expired answers`}
            />
            <Stat
              label="Blocked"
              value={formatCount(data.blocked)}
              detail={`${(data.total > 0 ? (data.blocked / data.total) * 100 : 0).toFixed(1)}% of queries`}
            />
            <Stat
              label="Average response time"
              value={formatDuration(data.average_latency_us)}
              detail={`${formatCount(data.failed)} failed or refused`}
            />
          </div>
          <TrafficChart data={trafficData(data)} />
          <Card>
            <CardHeader title="Queries by node" />
            {data.by_node.length === 0 ? (
              <p className="px-4 pb-4 text-sm text-text-muted">No nodes have joined yet.</p>
            ) : (
              <TableWrap>
                <Table>
                  <thead>
                    <tr>
                      <Th>Node</Th>
                      <Th>Site</Th>
                      <Th className="text-right">Queries</Th>
                      <Th className="text-right">Blocked</Th>
                      <Th className="text-right">Average response time</Th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.by_node.map((node) => (
                      <tr key={node.node_id}>
                        <Td className="font-medium">{node.node_name}</Td>
                        <Td>{node.site_name}</Td>
                        <Td className="text-right">{formatCount(node.total)}</Td>
                        <Td className="text-right">{formatCount(node.blocked)}</Td>
                        <Td className="text-right">{formatDuration(node.average_latency_us)}</Td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
              </TableWrap>
            )}
          </Card>
        </div>
      )}
    </>
  );
}
