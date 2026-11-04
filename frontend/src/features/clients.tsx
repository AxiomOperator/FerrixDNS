import { useQuery } from "@tanstack/react-query";
import { Pencil, Plus, Trash2 } from "lucide-react";
import { type FormEvent, useEffect, useState } from "react";

import { Empty, ErrorState, Loading, PageHeader, ReadOnlyNotice } from "@/components/states";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { ConfirmDialog, Dialog } from "@/components/ui/dialog";
import { Field, Input } from "@/components/ui/form";
import { Table, TableWrap, Td, Th } from "@/components/ui/table";
import { type Client, api, queries, usePolicyMutation } from "@/lib/api/hooks";
import { formatCount, timeAgo } from "@/lib/format";

function splitList(value: string): string[] {
  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function ClientDialog({
  open,
  client,
  onClose,
}: {
  open: boolean;
  client?: Client;
  onClose: () => void;
}) {
  const [name, setName] = useState("");
  const [addresses, setAddresses] = useState("");
  const [groups, setGroups] = useState("");
  const known = client?.known === true;

  useEffect(() => {
    if (open) {
      setName(client?.name ?? "");
      setAddresses(client?.addresses.join(", ") ?? "");
      setGroups(client?.groups.join(", ") ?? "");
    }
  }, [open, client]);

  const save = usePolicyMutation(
    () => {
      const body = { name, addresses: splitList(addresses), groups: splitList(groups) };
      return known && client ? api.updateClient(client.id, body) : api.createClient(body);
    },
    known ? "Client updated" : "Client named",
  );

  function submit(event: FormEvent) {
    event.preventDefault();
    save.mutate(undefined, { onSuccess: onClose });
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!next) onClose();
      }}
      title={known ? "Edit client" : "Name a client"}
      description="Clients are identified by their source address, so a device behind NAT or with a changing address may not match reliably."
    >
      <form className="space-y-4" onSubmit={submit}>
        <Field label="Name" htmlFor="client-name">
          <Input
            id="client-name"
            required
            autoComplete="off"
            placeholder="Living room TV"
            value={name}
            onChange={(event) => setName(event.target.value)}
          />
        </Field>
        <Field label="Addresses" htmlFor="client-addresses" hint="IP addresses or networks, separated by commas.">
          <Input
            id="client-addresses"
            required
            autoComplete="off"
            placeholder="192.168.1.50"
            value={addresses}
            onChange={(event) => setAddresses(event.target.value)}
          />
        </Field>
        <Field label="Groups (optional)" htmlFor="client-groups" hint="Group names, separated by commas.">
          <Input
            id="client-groups"
            autoComplete="off"
            placeholder="kids"
            value={groups}
            onChange={(event) => setGroups(event.target.value)}
          />
        </Field>
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" disabled={save.isPending}>
            Save client
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

export function ClientsPage({ readOnly }: { readOnly: boolean }) {
  const clients = useQuery(queries.clients());
  const [dialogOpen, setDialogOpen] = useState(false);
  const [selected, setSelected] = useState<Client>();
  const [deleting, setDeleting] = useState<Client>();
  const remove = usePolicyMutation((client: Client) => api.deleteClient(client.id), "Client removed");

  function open(client?: Client) {
    setSelected(client);
    setDialogOpen(true);
  }

  return (
    <>
      <PageHeader
        title="Clients"
        description="Devices using this node. Name one to give it its own rules."
        actions={
          <Button variant="primary" disabled={readOnly} onClick={() => open()}>
            <Plus aria-hidden className="size-4" />
            Add client
          </Button>
        }
      />
      {readOnly && <ReadOnlyNotice />}
      <Card>
        {clients.isPending && <Loading />}
        {clients.isError && <ErrorState error={clients.error} onRetry={() => void clients.refetch()} />}
        {clients.data?.length === 0 && (
          <Empty title="No clients yet">Point a device&apos;s DNS at this node, and it will appear here.</Empty>
        )}
        {clients.data && clients.data.length > 0 && (
          <TableWrap>
            <Table>
              <thead>
                <tr>
                  <Th>Client</Th>
                  <Th>Addresses</Th>
                  <Th>Groups</Th>
                  <Th className="text-right">Queries (7 days)</Th>
                  <Th>Last seen</Th>
                  <Th>
                    <span className="sr-only">Actions</span>
                  </Th>
                </tr>
              </thead>
              <tbody>
                {clients.data.map((client) => (
                  <tr key={client.id}>
                    <Td className="whitespace-nowrap">
                      {client.known ? (
                        <span className="font-medium">{client.name ?? client.id}</span>
                      ) : (
                        <Badge>Unnamed</Badge>
                      )}
                    </Td>
                    <Td className="text-text-secondary">{client.addresses.join(", ")}</Td>
                    <Td className="text-text-secondary">{client.groups.join(", ") || "None"}</Td>
                    <Td className="text-right">{formatCount(client.query_count)}</Td>
                    <Td className="whitespace-nowrap text-text-secondary">
                      {client.last_seen_at ? timeAgo(client.last_seen_at) : "Not seen"}
                    </Td>
                    <Td className="whitespace-nowrap text-right">
                      {client.known ? (
                        <>
                          <Button
                            variant="ghost"
                            size="icon"
                            disabled={readOnly}
                            aria-label={`Edit ${client.name ?? client.id}`}
                            onClick={() => open(client)}
                          >
                            <Pencil aria-hidden className="size-4" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon"
                            disabled={readOnly}
                            aria-label={`Remove ${client.name ?? client.id}`}
                            onClick={() => setDeleting(client)}
                          >
                            <Trash2 aria-hidden className="size-4" />
                          </Button>
                        </>
                      ) : (
                        <Button size="sm" disabled={readOnly} onClick={() => open(client)}>
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
      <ClientDialog open={dialogOpen} client={selected} onClose={() => setDialogOpen(false)} />
      <ConfirmDialog
        open={deleting !== undefined}
        onOpenChange={(next) => {
          if (!next) setDeleting(undefined);
        }}
        title="Remove this client?"
        description={`${deleting?.name ?? "This client"} goes back to being an unnamed address.`}
        confirmLabel="Remove client"
        pending={remove.isPending}
        onConfirm={() => {
          if (deleting) remove.mutate(deleting, { onSettled: () => setDeleting(undefined) });
        }}
      />
    </>
  );
}
