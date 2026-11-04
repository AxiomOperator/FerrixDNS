import { zodResolver } from "@hookform/resolvers/zod";
import { useQuery } from "@tanstack/react-query";
import { Plus, RefreshCw, Trash2 } from "lucide-react";
import { useEffect, useState } from "react";
import { useForm } from "react-hook-form";
import { z } from "zod";

import { Empty, ErrorState, Loading, PageHeader, ReadOnlyNotice } from "@/components/states";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { ConfirmDialog, Dialog } from "@/components/ui/dialog";
import { Field, Input, Select } from "@/components/ui/form";
import { Switch } from "@/components/ui/switch";
import { Table, TableWrap, Td, Th } from "@/components/ui/table";
import { type List, api, queries, usePolicyMutation } from "@/lib/api/hooks";
import { formatCount, timeAgo } from "@/lib/format";

const schema = z.object({
  name: z.string().trim().min(1, "Enter a name"),
  url: z.url("Enter a full URL, starting with https://"),
  format: z.enum(["hosts", "domains", "adblock"]),
  action: z.enum(["deny", "allow"]),
  group: z.string(),
  refresh_seconds: z.number(),
});

type FormValues = z.infer<typeof schema>;

const EMPTY: FormValues = {
  name: "",
  url: "",
  format: "hosts",
  action: "deny",
  group: "",
  refresh_seconds: 86_400,
};

function AddListDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const groups = useQuery(queries.groups());
  const { register, handleSubmit, reset, formState } = useForm<FormValues>({
    resolver: zodResolver(schema),
    defaultValues: EMPTY,
  });
  useEffect(() => {
    if (open) reset(EMPTY);
  }, [open, reset]);

  const create = usePolicyMutation(
    (values: FormValues) =>
      api.createList({
        name: values.name,
        url: values.url,
        format: values.format,
        action: values.action,
        groups: values.group ? [values.group] : [],
        refresh_seconds: values.refresh_seconds,
      }),
    "List added. It's downloading now.",
  );

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!next) onClose();
      }}
      title="Add a source"
      description="The node downloads the list now and on the schedule you choose."
    >
      <form
        className="space-y-4"
        onSubmit={(event) =>
          void handleSubmit((values) => create.mutate(values, { onSuccess: onClose }))(event)
        }
      >
        <Field label="Name" htmlFor="list-name" error={formState.errors.name?.message}>
          <Input id="list-name" autoComplete="off" placeholder="Ad and tracker hosts" {...register("name")} />
        </Field>
        <Field label="URL" htmlFor="list-url" error={formState.errors.url?.message}>
          <Input
            id="list-url"
            autoComplete="off"
            placeholder="https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
            {...register("url")}
          />
        </Field>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Format" htmlFor="list-format">
            <Select id="list-format" {...register("format")}>
              <option value="hosts">Hosts file</option>
              <option value="domains">One domain per line</option>
              <option value="adblock">Adblock (domain rules)</option>
            </Select>
          </Field>
          <Field label="Action" htmlFor="list-action">
            <Select id="list-action" {...register("action")}>
              <option value="deny">Block these domains</option>
              <option value="allow">Allow these domains</option>
            </Select>
          </Field>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Applies to" htmlFor="list-group">
            <Select id="list-group" {...register("group")}>
              <option value="">Everyone</option>
              {groups.data?.map((group) => (
                <option key={group.id} value={group.id}>
                  Group: {group.id}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="Check for updates" htmlFor="list-refresh">
            <Select id="list-refresh" {...register("refresh_seconds", { valueAsNumber: true })}>
              <option value={3600}>Every hour</option>
              <option value={21600}>Every 6 hours</option>
              <option value={86400}>Every day</option>
              <option value={604800}>Every week</option>
            </Select>
          </Field>
        </div>
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" disabled={create.isPending}>
            Add source
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

function ListStatus({ list }: { list: List }) {
  if (!list.url) return <Badge>In policy file</Badge>;
  if (list.last_error) {
    return <Badge tone="error">{list.artifact_sha256 ? "Update failed" : "Download failed"}</Badge>;
  }
  if (!list.last_checked_at) return <Badge tone="warning">Downloading</Badge>;
  return <Badge tone="success">Up to date</Badge>;
}

export function ListsPage({ readOnly }: { readOnly: boolean }) {
  const lists = useQuery(queries.lists());
  const [adding, setAdding] = useState(false);
  const [deleting, setDeleting] = useState<List>();

  const toggle = usePolicyMutation((list: List) => api.updateList(list.id, { enabled: !list.enabled }));
  const refresh = usePolicyMutation((list: List) => api.refreshList(list.id), "Checking for updates");
  const remove = usePolicyMutation((list: List) => api.deleteList(list.id), "Source removed");

  return (
    <>
      <PageHeader
        title="Sources"
        description="Blocklists and allowlists this node subscribes to."
        actions={
          <Button variant="primary" disabled={readOnly} onClick={() => setAdding(true)}>
            <Plus aria-hidden className="size-4" />
            Add source
          </Button>
        }
      />
      {readOnly && <ReadOnlyNotice />}
      <Card>
        {lists.isPending && <Loading />}
        {lists.isError && <ErrorState error={lists.error} onRetry={() => void lists.refetch()} />}
        {lists.data?.length === 0 && (
          <Empty title="No sources yet">Add a blocklist to start filtering ads and trackers.</Empty>
        )}
        {lists.data && lists.data.length > 0 && (
          <TableWrap>
            <Table>
              <thead>
                <tr>
                  <Th>Source</Th>
                  <Th>Status</Th>
                  <Th className="text-right">Entries</Th>
                  <Th>Applies to</Th>
                  <Th>Last checked</Th>
                  <Th>Enabled</Th>
                  <Th>
                    <span className="sr-only">Actions</span>
                  </Th>
                </tr>
              </thead>
              <tbody>
                {lists.data.map((list) => {
                  const name = list.name ?? list.id;
                  return (
                    <tr key={list.id}>
                      <Td className="max-w-96">
                        <span className="block truncate font-medium" title={name}>
                          {name}
                          {list.action === "allow" && " (allowlist)"}
                        </span>
                        {list.url && (
                          <span className="block truncate text-xs text-text-muted" title={list.url}>
                            {list.url}
                          </span>
                        )}
                        {list.last_error && (
                          <span role="alert" className="block text-xs font-medium text-danger">
                            {list.last_error}
                            {list.artifact_sha256 ? ". The previous download stays active." : ""}
                          </span>
                        )}
                      </Td>
                      <Td>
                        <ListStatus list={list} />
                      </Td>
                      <Td className="text-right whitespace-nowrap">
                        {formatCount(list.entry_count)}
                        {list.invalid_line_count > 0 && (
                          <span className="block text-xs text-text-muted">
                            {formatCount(list.invalid_line_count)} lines skipped
                          </span>
                        )}
                      </Td>
                      <Td className="whitespace-nowrap text-text-secondary">
                        {list.groups.length > 0 ? list.groups.join(", ") : "Everyone"}
                      </Td>
                      <Td className="whitespace-nowrap text-text-secondary">
                        {list.last_checked_at ? timeAgo(list.last_checked_at) : "Not yet"}
                      </Td>
                      <Td>
                        <Switch
                          checked={list.enabled}
                          disabled={readOnly || toggle.isPending}
                          label={`Enable ${name}`}
                          onCheckedChange={() => toggle.mutate(list)}
                        />
                      </Td>
                      <Td className="whitespace-nowrap text-right">
                        {list.url && (
                          <Button
                            variant="ghost"
                            size="icon"
                            disabled={readOnly || refresh.isPending}
                            aria-label={`Check ${name} for updates`}
                            onClick={() => refresh.mutate(list)}
                          >
                            <RefreshCw aria-hidden className="size-4" />
                          </Button>
                        )}
                        <Button
                          variant="ghost"
                          size="icon"
                          disabled={readOnly}
                          aria-label={`Remove ${name}`}
                          onClick={() => setDeleting(list)}
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
      <AddListDialog open={adding} onClose={() => setAdding(false)} />
      <ConfirmDialog
        open={deleting !== undefined}
        onOpenChange={(open) => {
          if (!open) setDeleting(undefined);
        }}
        title="Remove this source?"
        description={`Domains from ${deleting?.name ?? "this list"} stop being filtered right away.`}
        confirmLabel="Remove source"
        pending={remove.isPending}
        onConfirm={() => {
          if (deleting) remove.mutate(deleting, { onSettled: () => setDeleting(undefined) });
        }}
      />
    </>
  );
}
