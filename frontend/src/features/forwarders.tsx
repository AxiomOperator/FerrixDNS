import { useQuery } from "@tanstack/react-query";
import { Pencil, Plus, Trash2 } from "lucide-react";
import { type FormEvent, useEffect, useState } from "react";

import { Empty, ErrorState, Loading, PageHeader, ReadOnlyNotice } from "@/components/states";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { ConfirmDialog, Dialog } from "@/components/ui/dialog";
import { Field, Input } from "@/components/ui/form";
import { Switch } from "@/components/ui/switch";
import { Table, TableWrap, Td, Th } from "@/components/ui/table";
import { type ForwardZone, api, queries, usePolicyMutation } from "@/lib/api/hooks";
import { formatCount, splitList } from "@/lib/format";

function ForwarderDialog({
  open,
  zone,
  onClose,
}: {
  open: boolean;
  zone?: ForwardZone;
  onClose: () => void;
}) {
  const [zones, setZones] = useState("");
  const [servers, setServers] = useState("");
  const [loadBalance, setLoadBalance] = useState(false);

  useEffect(() => {
    if (open) {
      setZones(zone?.zones.join(", ") ?? "");
      setServers(zone?.servers.join(", ") ?? "");
      setLoadBalance(zone?.load_balance ?? false);
    }
  }, [open, zone]);

  const save = usePolicyMutation(
    () => {
      const body = { zones: splitList(zones), servers: splitList(servers), load_balance: loadBalance };
      return zone ? api.updateForwarder(zone.id, body) : api.createForwarder(body);
    },
    "Forwarding saved and active",
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
      title={zone ? "Edit forwarding" : "Add forwarding"}
      description="These names go only to these servers. If the servers fail, queries fail too, so private names never reach your public upstreams."
    >
      <form className="space-y-4" onSubmit={submit}>
        <Field
          label="Domains and networks"
          htmlFor="forward-zones"
          hint="Separated by commas. A network sends its reverse lookups here, which is also how this node learns device host names."
        >
          <Input
            id="forward-zones"
            required
            autoComplete="off"
            placeholder="lan, 192.168.1.0/24"
            value={zones}
            onChange={(event) => setZones(event.target.value)}
          />
        </Field>
        <Field
          label="Servers"
          htmlFor="forward-servers"
          hint="Separated by commas. Usually your router's address. Encrypted servers use the same format as --upstream."
        >
          <Input
            id="forward-servers"
            required
            autoComplete="off"
            placeholder="192.168.1.1"
            value={servers}
            onChange={(event) => setServers(event.target.value)}
          />
        </Field>
        <div className="flex items-start gap-3">
          <div className="pt-0.5">
            <Switch label="Load balance" checked={loadBalance} onCheckedChange={setLoadBalance} />
          </div>
          <div className="min-w-0">
            <p className="text-sm font-medium">Load balance</p>
            <p className="text-sm text-text-secondary">
              Shares queries between the servers, so they all need to give the same answers. When off,
              they&apos;re tried in order, and the later ones are only used if the earlier ones fail.
            </p>
          </div>
        </div>
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" disabled={save.isPending}>
            Save forwarding
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

export function ForwardersPage({ readOnly }: { readOnly: boolean }) {
  const zones = useQuery(queries.forwarders());
  const [dialogOpen, setDialogOpen] = useState(false);
  const [selected, setSelected] = useState<ForwardZone>();
  const [deleting, setDeleting] = useState<ForwardZone>();
  const remove = usePolicyMutation((zone: ForwardZone) => api.deleteForwarder(zone.id), "Forwarding removed");

  function open(zone?: ForwardZone) {
    setSelected(zone);
    setDialogOpen(true);
  }

  return (
    <>
      <PageHeader
        title="Conditional forwarding"
        description="Send some names to specific servers, such as your router, instead of your upstreams."
        actions={
          <Button variant="primary" disabled={readOnly} onClick={() => open()}>
            <Plus aria-hidden className="size-4" />
            Add forwarding
          </Button>
        }
      />
      {readOnly && <ReadOnlyNotice />}
      <Card>
        {zones.isPending && <Loading />}
        {zones.isError && <ErrorState error={zones.error} onRetry={() => void zones.refetch()} />}
        {zones.data?.length === 0 && (
          <Empty title="Nothing is forwarded yet">
            Add your router here so names like nas.lan resolve, and so devices show their host names.
          </Empty>
        )}
        {zones.data && zones.data.length > 0 && (
          <TableWrap>
            <Table>
              <thead>
                <tr>
                  <Th>Domains and networks</Th>
                  <Th>Servers</Th>
                  <Th className="text-right">Answers</Th>
                  <Th className="text-right">Failures</Th>
                  <Th>
                    <span className="sr-only">Actions</span>
                  </Th>
                </tr>
              </thead>
              <tbody>
                {zones.data.map((zone) => {
                  const label = zone.zones.join(", ");
                  return (
                    <tr key={zone.id}>
                      <Td className="font-medium">{label}</Td>
                      <Td className="text-text-secondary">
                        {zone.servers.join(", ")}
                        {zone.load_balance && zone.servers.length > 1 && " (load balanced)"}
                      </Td>
                      <Td className="text-right">
                        {formatCount(zone.stats.reduce((sum, server) => sum + server.responses, 0))}
                      </Td>
                      <Td className="text-right">
                        {formatCount(zone.stats.reduce((sum, server) => sum + server.failures, 0))}
                      </Td>
                      <Td className="whitespace-nowrap text-right">
                        <Button
                          variant="ghost"
                          size="icon"
                          disabled={readOnly}
                          aria-label={`Edit ${label}`}
                          onClick={() => open(zone)}
                        >
                          <Pencil aria-hidden className="size-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          disabled={readOnly}
                          aria-label={`Remove ${label}`}
                          onClick={() => setDeleting(zone)}
                        >
                          <Trash2 aria-hidden className="size-4" />
                        </Button>
                      </Td>
                    </tr>
                  );
                })}
              </tbody>
            </Table>
          </TableWrap>
        )}
      </Card>
      <p className="mt-2 text-xs text-text-muted">Counts are since the node last started.</p>
      <ForwarderDialog open={dialogOpen} zone={selected} onClose={() => setDialogOpen(false)} />
      <ConfirmDialog
        open={deleting !== undefined}
        onOpenChange={(next) => {
          if (!next) setDeleting(undefined);
        }}
        title="Remove this forwarding?"
        description={`Names under ${deleting?.zones.join(", ") ?? "these zones"} go back to your normal upstreams, or stay unanswered if they're private.`}
        confirmLabel="Remove forwarding"
        pending={remove.isPending}
        onConfirm={() => {
          if (deleting) remove.mutate(deleting, { onSettled: () => setDeleting(undefined) });
        }}
      />
    </>
  );
}
