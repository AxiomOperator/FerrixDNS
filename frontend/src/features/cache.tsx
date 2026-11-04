import { useQuery } from "@tanstack/react-query";
import { useState } from "react";

import { Empty, ErrorState, Loading, PageHeader } from "@/components/states";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { ConfirmDialog } from "@/components/ui/dialog";
import { api, queries, usePolicyMutation } from "@/lib/api/hooks";
import { formatBytes, formatCount } from "@/lib/format";

function Stat({ label, value, detail }: { label: string; value: string; detail?: string }) {
  return (
    <Card className="p-4">
      <p className="text-xs font-medium text-text-muted">{label}</p>
      <p className="mt-1 text-2xl font-semibold">{value}</p>
      {detail && <p className="mt-0.5 text-xs text-text-muted">{detail}</p>}
    </Card>
  );
}

export function CachePage() {
  const cache = useQuery(queries.cache());
  const [confirming, setConfirming] = useState(false);
  const flush = usePolicyMutation(() => api.flushCache(), "Cache flushed");
  const data = cache.data;
  const lookups = data ? data.hits + data.misses : 0;

  return (
    <>
      <PageHeader
        title="Cache"
        description="Recent upstream answers, reused until their TTL runs out. Rules are still checked on every cached answer, so changing a rule never needs a flush."
        actions={
          <Button disabled={!data?.enabled} onClick={() => setConfirming(true)}>
            Flush cache
          </Button>
        }
      />
      {cache.isPending && <Loading />}
      {cache.isError && <ErrorState error={cache.error} onRetry={() => void cache.refetch()} />}
      {data && !data.enabled && (
        <Card>
          <Empty title="The cache is off">Give it some memory in Settings to turn it on.</Empty>
        </Card>
      )}
      {data?.enabled && (
        <>
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
            <Stat
              label="Hit rate"
              value={lookups > 0 ? `${((data.hits / lookups) * 100).toFixed(1)}%` : "No data"}
              detail={`${formatCount(lookups)} lookups`}
            />
            <Stat label="Hits" value={formatCount(data.hits)} detail="Answered without going upstream" />
            <Stat label="Entries" value={formatCount(data.entries)} />
            <Stat
              label="Memory"
              value={formatBytes(data.bytes)}
              detail={`Limit ${formatBytes(data.max_bytes)}`}
            />
          </div>
          <p className="mt-2 text-xs text-text-muted">Counts are since the node last started.</p>
        </>
      )}
      <ConfirmDialog
        open={confirming}
        onOpenChange={setConfirming}
        title="Flush the cache?"
        description="Every cached answer is removed, so the next lookups go upstream. This is rarely needed."
        confirmLabel="Flush cache"
        pending={flush.isPending}
        onConfirm={() => flush.mutate(undefined, { onSettled: () => setConfirming(false) })}
      />
    </>
  );
}
