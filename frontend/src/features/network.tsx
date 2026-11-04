import { useQuery } from "@tanstack/react-query";
import { useState } from "react";

import { ClientDialog } from "./clients";

import { Empty, ErrorState, Loading, PageHeader, ReadOnlyNotice } from "@/components/states";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Table, TableWrap, Td, Th } from "@/components/ui/table";
import { type Client, type NetworkDevice, queries } from "@/lib/api/hooks";
import { formatCount, timeAgo } from "@/lib/format";

/** A draft client for naming a device, identified by the most stable thing known about it. */
function draftClient(device: NetworkDevice): Client {
  return {
    id: device.id,
    known: false,
    name: device.hostname?.split(".")[0] ?? null,
    addresses: device.addresses,
    macs: device.mac ? [device.mac] : [],
    hostnames: [],
    groups: [],
    query_count: device.query_count ?? 0,
    last_seen_at: device.last_query_at ?? null,
  };
}

function Status({ device }: { device: NetworkDevice }) {
  if (device.rate_limited) return <Badge tone="danger">Over query limit</Badge>;
  if (device.on_network) return <Badge tone="success">On network</Badge>;
  return <Badge>Not seen now</Badge>;
}

export function NetworkPage({ readOnly }: { readOnly: boolean }) {
  const devices = useQuery(queries.devices());
  const [naming, setNaming] = useState<NetworkDevice>();
  const client = naming ? draftClient(naming) : undefined;

  return (
    <>
      <PageHeader
        title="Network"
        description="Devices this node can see on its network, and any others that have asked it something."
      />
      {readOnly && <ReadOnlyNotice />}
      <Card>
        {devices.isPending && <Loading />}
        {devices.isError && <ErrorState error={devices.error} onRetry={() => void devices.refetch()} />}
        {devices.data?.length === 0 && (
          <Empty title="No devices yet">
            Devices appear here once this node has talked to them, or they send it a query.
          </Empty>
        )}
        {devices.data && devices.data.length > 0 && (
          <TableWrap>
            <Table>
              <thead>
                <tr>
                  <Th>Device</Th>
                  <Th>Addresses</Th>
                  <Th>MAC address</Th>
                  <Th>Status</Th>
                  <Th className="text-right">Queries (7 days)</Th>
                  <Th>Last active</Th>
                  <Th>
                    <span className="sr-only">Actions</span>
                  </Th>
                </tr>
              </thead>
              <tbody>
                {devices.data.map((device) => (
                  <tr key={device.id}>
                    <Td className="whitespace-nowrap">
                      <div className="font-medium">
                        {device.client_name ?? device.hostname ?? "Unknown device"}
                      </div>
                      {device.client_name && device.hostname && (
                        <div className="text-xs text-text-muted">{device.hostname}</div>
                      )}
                    </Td>
                    <Td className="text-text-secondary">{device.addresses.join(", ")}</Td>
                    <Td className="whitespace-nowrap font-mono text-xs text-text-secondary">
                      {device.mac ?? "Not known"}
                    </Td>
                    <Td className="whitespace-nowrap">
                      <Status device={device} />
                    </Td>
                    <Td className="text-right">
                      {device.query_count === null || device.query_count === undefined
                        ? "Not known"
                        : formatCount(device.query_count)}
                    </Td>
                    <Td className="whitespace-nowrap text-text-secondary">
                      {device.last_active_at ? timeAgo(device.last_active_at) : "Not known"}
                    </Td>
                    <Td className="whitespace-nowrap text-right">
                      {device.client_id ? (
                        <span className="text-sm text-text-secondary">
                          {device.client_name ?? device.client_id}
                        </span>
                      ) : (
                        <Button size="sm" disabled={readOnly} onClick={() => setNaming(device)}>
                          Name client
                        </Button>
                      )}
                    </Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          </TableWrap>
        )}
      </Card>
      <p className="mt-2 text-xs text-text-muted">
        MAC addresses are only visible for devices on the same network segment as this node. Devices
        are remembered for 90 days, unless query logging is reduced in Settings.
      </p>
      <ClientDialog open={naming !== undefined} client={client} onClose={() => setNaming(undefined)} />
    </>
  );
}
