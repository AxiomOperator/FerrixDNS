import { useQuery } from "@tanstack/react-query";
import { Pencil, Plus, Trash2 } from "lucide-react";
import { type FormEvent, useEffect, useState } from "react";

import { Empty, ErrorState, Loading, PageHeader, ReadOnlyNotice } from "@/components/states";
import { Button } from "@/components/ui/button";
import { Card, CardHeader } from "@/components/ui/card";
import { ConfirmDialog, Dialog } from "@/components/ui/dialog";
import { Field, Input, Select } from "@/components/ui/form";
import { Table, TableWrap, Td, Th } from "@/components/ui/table";
import { type LocalRecord, api, queries, usePolicyMutation } from "@/lib/api/hooks";

const TYPE_LABELS: Record<LocalRecord["type"], string> = {
  a: "A",
  aaaa: "AAAA",
  cname: "CNAME",
  ptr: "PTR",
};

const VALUE_HINTS: Record<LocalRecord["type"], { label: string; placeholder: string }> = {
  a: { label: "IPv4 address", placeholder: "192.168.1.10" },
  aaaa: { label: "IPv6 address", placeholder: "fd00::10" },
  cname: { label: "Target name, in a local zone", placeholder: "nas.home.arpa" },
  ptr: { label: "Target name", placeholder: "nas.home.arpa" },
};

function RecordDialog({
  open,
  record,
  onClose,
}: {
  open: boolean;
  record?: LocalRecord;
  onClose: () => void;
}) {
  const [name, setName] = useState("");
  const [type, setType] = useState<LocalRecord["type"]>("a");
  const [value, setValue] = useState("");
  const [ttl, setTtl] = useState(300);

  useEffect(() => {
    if (open) {
      setName(record?.name ?? "");
      setType(record?.type ?? "a");
      setValue(record?.value ?? "");
      setTtl(record?.ttl_seconds ?? 300);
    }
  }, [open, record]);

  const save = usePolicyMutation(
    () => {
      const body = { name, type, value, ttl_seconds: ttl };
      return record ? api.updateRecord(record.id, body) : api.createRecord(body);
    },
    record ? "Record updated and active" : "Record added and active",
  );

  function submit(event: FormEvent) {
    event.preventDefault();
    save.mutate(undefined, { onSuccess: onClose });
  }

  const hint = VALUE_HINTS[type];
  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!next) onClose();
      }}
      title={record ? "Edit record" : "Add record"}
      description="Private addresses also answer reverse lookups automatically."
    >
      <form className="space-y-4" onSubmit={submit}>
        <Field label="Name" htmlFor="record-name">
          <Input
            id="record-name"
            required
            autoComplete="off"
            placeholder="nas.home.arpa"
            value={name}
            onChange={(event) => setName(event.target.value)}
          />
        </Field>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Type" htmlFor="record-type">
            <Select
              id="record-type"
              value={type}
              onChange={(event) => setType(event.target.value as LocalRecord["type"])}
            >
              {Object.entries(TYPE_LABELS).map(([key, label]) => (
                <option key={key} value={key}>
                  {label}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="TTL (seconds)" htmlFor="record-ttl">
            <Input
              id="record-ttl"
              type="number"
              min={0}
              max={86400}
              required
              value={ttl}
              onChange={(event) => setTtl(Number(event.target.value))}
            />
          </Field>
        </div>
        <Field label={hint.label} htmlFor="record-value">
          <Input
            id="record-value"
            required
            autoComplete="off"
            placeholder={hint.placeholder}
            value={value}
            onChange={(event) => setValue(event.target.value)}
          />
        </Field>
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" disabled={save.isPending}>
            Save record
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

function ZonesCard({ readOnly }: { readOnly: boolean }) {
  const zones = useQuery(queries.zones());
  const [name, setName] = useState("");
  const [deleting, setDeleting] = useState<string>();
  const create = usePolicyMutation(() => api.createZone({ name }), "Zone added and active");
  const remove = usePolicyMutation((zone: string) => api.deleteZone(zone), "Zone removed");

  function submit(event: FormEvent) {
    event.preventDefault();
    create.mutate(undefined, { onSuccess: () => setName("") });
  }

  return (
    <Card className="mb-4">
      <CardHeader
        title="Zones"
        description="This node answers every name in a zone itself, and never sends them upstream. home.arpa is reserved for home networks."
      />
      <form className="flex flex-wrap gap-2 px-4 pb-4" onSubmit={submit}>
        <div className="min-w-48 flex-1">
          <label htmlFor="zone-name" className="sr-only">
            Zone name
          </label>
          <Input
            id="zone-name"
            required
            autoComplete="off"
            disabled={readOnly}
            placeholder="home.arpa"
            value={name}
            onChange={(event) => setName(event.target.value)}
          />
        </div>
        <Button type="submit" disabled={readOnly || create.isPending}>
          Add zone
        </Button>
      </form>
      {zones.isPending && <Loading />}
      {zones.isError && <ErrorState error={zones.error} onRetry={() => void zones.refetch()} />}
      {zones.data?.length === 0 && <Empty title="No local zones yet">Add a zone, then add records to it.</Empty>}
      {zones.data && zones.data.length > 0 && (
        <TableWrap>
          <Table>
            <thead>
              <tr>
                <Th>Zone</Th>
                <Th className="text-right">Records</Th>
                <Th>
                  <span className="sr-only">Actions</span>
                </Th>
              </tr>
            </thead>
            <tbody>
              {zones.data.map((zone) => (
                <tr key={zone.name}>
                  <Td className="font-medium">{zone.name}</Td>
                  <Td className="text-right">{zone.record_count}</Td>
                  <Td className="text-right">
                    <Button
                      variant="ghost"
                      size="icon"
                      disabled={readOnly}
                      aria-label={`Remove zone ${zone.name}`}
                      onClick={() => setDeleting(zone.name)}
                    >
                      <Trash2 aria-hidden className="size-4" />
                    </Button>
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        </TableWrap>
      )}
      <ConfirmDialog
        open={deleting !== undefined}
        onOpenChange={(next) => {
          if (!next) setDeleting(undefined);
        }}
        title={`Remove ${deleting ?? "this zone"}?`}
        description="Its names go back to being answered upstream. Zones with records can't be removed."
        confirmLabel="Remove zone"
        pending={remove.isPending}
        onConfirm={() => {
          if (deleting) remove.mutate(deleting, { onSettled: () => setDeleting(undefined) });
        }}
      />
    </Card>
  );
}

export function LocalDnsPage({ readOnly }: { readOnly: boolean }) {
  const records = useQuery(queries.records());
  const [dialogOpen, setDialogOpen] = useState(false);
  const [selected, setSelected] = useState<LocalRecord>();
  const [deleting, setDeleting] = useState<LocalRecord>();
  const remove = usePolicyMutation((record: LocalRecord) => api.deleteRecord(record.id), "Record deleted");

  function open(record?: LocalRecord) {
    setSelected(record);
    setDialogOpen(true);
  }

  return (
    <>
      <PageHeader
        title="Local DNS"
        description="Names for devices on your network. Block rules still apply to them, but subscribed lists don't."
        actions={
          <Button variant="primary" disabled={readOnly} onClick={() => open()}>
            <Plus aria-hidden className="size-4" />
            Add record
          </Button>
        }
      />
      {readOnly && <ReadOnlyNotice />}
      <ZonesCard readOnly={readOnly} />
      <Card>
        <CardHeader title="Records" />
        {records.isPending && <Loading />}
        {records.isError && <ErrorState error={records.error} onRetry={() => void records.refetch()} />}
        {records.data?.length === 0 && <Empty title="No records yet" />}
        {records.data && records.data.length > 0 && (
          <TableWrap>
            <Table>
              <thead>
                <tr>
                  <Th>Name</Th>
                  <Th>Type</Th>
                  <Th>Value</Th>
                  <Th className="text-right">TTL</Th>
                  <Th>
                    <span className="sr-only">Actions</span>
                  </Th>
                </tr>
              </thead>
              <tbody>
                {records.data.map((record) => (
                  <tr key={record.id}>
                    <Td className="font-medium">{record.name}</Td>
                    <Td className="text-text-secondary">{TYPE_LABELS[record.type]}</Td>
                    <Td className="text-text-secondary">{record.value}</Td>
                    <Td className="text-right text-text-secondary">{record.ttl_seconds} s</Td>
                    <Td className="whitespace-nowrap text-right">
                      <Button
                        variant="ghost"
                        size="icon"
                        disabled={readOnly}
                        aria-label={`Edit ${record.name}`}
                        onClick={() => open(record)}
                      >
                        <Pencil aria-hidden className="size-4" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon"
                        disabled={readOnly}
                        aria-label={`Delete ${record.name}`}
                        onClick={() => setDeleting(record)}
                      >
                        <Trash2 aria-hidden className="size-4" />
                      </Button>
                    </Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          </TableWrap>
        )}
      </Card>
      <RecordDialog open={dialogOpen} record={selected} onClose={() => setDialogOpen(false)} />
      <ConfirmDialog
        open={deleting !== undefined}
        onOpenChange={(next) => {
          if (!next) setDeleting(undefined);
        }}
        title="Delete this record?"
        description={`${deleting?.name ?? "This name"} stops resolving right away.`}
        confirmLabel="Delete record"
        pending={remove.isPending}
        onConfirm={() => {
          if (deleting) remove.mutate(deleting, { onSettled: () => setDeleting(undefined) });
        }}
      />
    </>
  );
}
