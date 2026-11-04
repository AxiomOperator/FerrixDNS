import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { Empty, ErrorState, Loading, PageHeader } from "@/components/states";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Table, TableWrap, Td, Th } from "@/components/ui/table";
import { type Schemas, errorMessage } from "@/lib/api/client";
import { api, queries } from "@/lib/api/hooks";
import { formatCount, formatDuration } from "@/lib/format";

export function UpstreamsPage() {
  const upstreams = useQuery(queries.upstreams());
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
        {upstreams.data?.length === 0 && <Empty title="No upstream servers" />}
        {upstreams.data && upstreams.data.length > 0 && (
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
                {upstreams.data.map((upstream, index) => (
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
    </>
  );
}
