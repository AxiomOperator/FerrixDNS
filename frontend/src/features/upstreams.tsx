import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { Empty, ErrorState, Loading, PageHeader } from "@/components/states";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Table, TableWrap, Td, Th } from "@/components/ui/table";
import { type Schemas, errorMessage } from "@/lib/api/client";
import { UpstreamHistory } from "@/features/upstream-history";
import { api, queries } from "@/lib/api/hooks";
import { formatCount, formatDuration } from "@/lib/format";

export function UpstreamsPage() {
  const upstreams = useQuery(queries.upstreams());
  const servers = upstreams.data?.filter((upstream) => !upstream.forward_zones);
  const zoneServers = upstreams.data?.filter((upstream) => upstream.forward_zones) ?? [];
  const client = useQueryClient();
  const [result, setResult] = useState<Schemas["UpstreamTestResult"]>();
  const test = useMutation({
    mutationFn: api.testUpstreams,
    onSuccess: (data) => {
      setResult(data);
      void client.invalidateQueries({ queryKey: ["upstreams"] });
    },
  });

  return (
    <>
      <PageHeader
        title="Upstreams"
        description="Servers this node forwards to. Change them, or how they share queries, in Settings."
        actions={
          <Button disabled={test.isPending} onClick={() => test.mutate()}>
            {test.isPending ? "Testing…" : "Test upstreams"}
          </Button>
        }
      />
      {test.isError && (
        <p role="alert" className="mb-4 text-sm font-medium text-danger">
          {errorMessage(test.error)}
        </p>
      )}
      {result && (
        <div role="status" className="mb-4 flex flex-wrap items-center gap-2 text-sm">
          <Badge tone={result.ok ? "success" : "error"}>{result.ok ? "Reachable" : "Unreachable"}</Badge>
          <span className="text-text-secondary">
            {result.ok
              ? `${result.server ?? "An upstream"} answered ${result.rcode ?? ""} in ${result.latency_ms} ms.`
              : `${result.message ?? "No upstream answered"} after ${result.latency_ms} ms.`}
          </span>
        </div>
      )}
      <Card>
        {upstreams.isPending && <Loading />}
        {upstreams.isError && <ErrorState error={upstreams.error} onRetry={() => void upstreams.refetch()} />}
        {servers?.length === 0 && <Empty title="No upstream servers" />}
        {servers && servers.length > 0 && (
          <TableWrap>
            <Table>
              <thead>
                <tr>
                  <Th>Order</Th>
                  <Th>Server</Th>
                  <Th className="text-right">Answers</Th>
                  <Th className="text-right">Failures</Th>
                  <Th className="text-right">Last response time</Th>
                </tr>
              </thead>
              <tbody>
                {servers.map((upstream, index) => (
                  <tr key={upstream.server}>
                    <Td>{index + 1}</Td>
                    <Td className="font-medium">{upstream.server}</Td>
                    <Td className="text-right">{formatCount(upstream.responses)}</Td>
                    <Td className="text-right">{formatCount(upstream.failures)}</Td>
                    <Td className="text-right">
                      {upstream.responses > 0 ? formatDuration(upstream.last_latency_us) : "None yet"}
                    </Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          </TableWrap>
        )}
      </Card>
      <p className="mt-2 text-xs text-text-muted">Counts are since the node last started.</p>
      <div className="mt-4 grid items-start gap-4 lg:grid-cols-2">
        {servers?.map((upstream) => <UpstreamHistory key={upstream.server} upstream={upstream} />)}
      </div>
      {zoneServers.length > 0 && (
        <>
          <h2 className="mt-6 mb-1 text-sm font-semibold">Conditional forwarding servers</h2>
          <p className="mb-3 text-xs text-text-muted">Each appears once a query has used it.</p>
          <div className="grid items-start gap-4 lg:grid-cols-2">
            {zoneServers.map((upstream) => (
              <div key={`${upstream.forward_zones}-${upstream.server}`}>
                <p className="mb-1 truncate text-xs text-text-secondary">For {upstream.forward_zones}</p>
                <UpstreamHistory upstream={upstream} />
              </div>
            ))}
          </div>
        </>
      )}
    </>
  );
}
