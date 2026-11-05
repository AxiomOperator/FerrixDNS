import { format } from "date-fns";
import { useState } from "react";
import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { Button } from "@/components/ui/button";
import { Card, CardHeader } from "@/components/ui/card";
import { Table, TableWrap, Td, Th } from "@/components/ui/table";
import { type Schemas } from "@/lib/api/client";
import { formatCount } from "@/lib/format";

interface Point {
  start: string;
  ms: number | null;
  responses: number;
  failures: number;
}

/** Every minute of the last hour, so quiet minutes show as gaps instead of being drawn across. */
function pointsFor(upstream: Schemas["UpstreamDto"], now: number): Point[] {
  const byMinute = new Map(upstream.history.map((minute) => [Date.parse(minute.start), minute]));
  const current = now - (now % 60_000);
  return Array.from({ length: 60 }, (_, index) => {
    const start = current - (59 - index) * 60_000;
    const minute = byMinute.get(start);
    return {
      start: new Date(start).toISOString(),
      ms: minute && minute.responses > 0 ? minute.average_latency_us / 1000 : null,
      responses: minute?.responses ?? 0,
      failures: minute?.failures ?? 0,
    };
  });
}

function PointTooltip({ active, payload }: { active?: boolean; payload?: readonly { payload?: Point }[] }) {
  const point = payload?.[0]?.payload;
  if (!active || !point) return null;
  return (
    <div className="rounded-md border border-border bg-surface px-3 py-2 text-xs shadow-md">
      <p className="mb-1 font-medium">{format(new Date(point.start), "HH:mm")}</p>
      <p className="flex justify-between gap-4 text-text-secondary">
        Response time <span className="font-medium text-text">{point.ms === null ? "None" : `${point.ms.toFixed(1)} ms`}</span>
      </p>
      <p className="flex justify-between gap-4 text-text-secondary">
        Answers <span className="font-medium text-text">{formatCount(point.responses)}</span>
      </p>
      <p className="flex justify-between gap-4 text-text-secondary">
        Failures <span className="font-medium text-text">{formatCount(point.failures)}</span>
      </p>
    </div>
  );
}

export function UpstreamHistory({ upstream }: { upstream: Schemas["UpstreamDto"] }) {
  const [showTable, setShowTable] = useState(false);
  const points = pointsFor(upstream, Date.now());
  const failures = points.reduce((total, point) => total + point.failures, 0);
  const active = points.filter((point) => point.responses + point.failures > 0);

  return (
    <Card>
      <CardHeader
        title={upstream.server}
        description={`Average response time per minute, last hour. ${formatCount(failures)} failures.`}
        actions={
          <Button size="sm" aria-pressed={showTable} onClick={() => setShowTable((value) => !value)}>
            {showTable ? "Show chart" : "Show table"}
          </Button>
        }
      />
      {showTable ? (
        <TableWrap className="max-h-48 overflow-y-auto">
          <Table>
            <thead>
              <tr>
                <Th>Time</Th>
                <Th className="text-right">Response time</Th>
                <Th className="text-right">Answers</Th>
                <Th className="text-right">Failures</Th>
              </tr>
            </thead>
            <tbody>
              {active.map((point) => (
                <tr key={point.start}>
                  <Td>{format(new Date(point.start), "HH:mm")}</Td>
                  <Td className="text-right">{point.ms === null ? "None" : `${point.ms.toFixed(1)} ms`}</Td>
                  <Td className="text-right">{formatCount(point.responses)}</Td>
                  <Td className="text-right">{formatCount(point.failures)}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
          {active.length === 0 && (
            <p className="px-4 py-6 text-center text-sm text-text-muted">No queries in the last hour.</p>
          )}
        </TableWrap>
      ) : (
        <div
          className="h-40 px-2 pb-2"
          role="img"
          aria-label={`Line chart of ${upstream.server}'s response time per minute over the last hour. Use Show table for the values.`}
        >
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={points} margin={{ top: 8, right: 12, left: 0, bottom: 0 }}>
              <CartesianGrid stroke="var(--grid)" vertical={false} />
              <XAxis
                dataKey="start"
                tickFormatter={(value: string) => format(new Date(value), "HH:mm")}
                tick={{ fontSize: 11, fill: "var(--text-muted)" }}
                tickLine={false}
                axisLine={{ stroke: "var(--border)" }}
                minTickGap={48}
              />
              <YAxis
                tick={{ fontSize: 11, fill: "var(--text-muted)" }}
                tickLine={false}
                axisLine={false}
                width={52}
                unit=" ms"
              />
              <Tooltip
                cursor={{ stroke: "var(--border-strong)" }}
                content={(props) => (
                  <PointTooltip
                    active={props.active}
                    payload={props.payload as readonly { payload?: Point }[] | undefined}
                  />
                )}
              />
              <Line
                type="monotone"
                dataKey="ms"
                name="Response time"
                stroke="var(--series-forwarded)"
                strokeWidth={2}
                dot={{ r: 2, strokeWidth: 0, fill: "var(--series-forwarded)" }}
                activeDot={{ r: 4, stroke: "var(--surface)", strokeWidth: 2 }}
                connectNulls={false}
                isAnimationActive={false}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      )}
    </Card>
  );
}
