import { useQuery } from "@tanstack/react-query";
import { Pencil, Plus, Trash2 } from "lucide-react";
import { type FormEvent, useEffect, useState } from "react";

import { Empty, ErrorState, Loading, PageHeader, ReadOnlyNotice } from "@/components/states";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { ConfirmDialog, Dialog } from "@/components/ui/dialog";
import { Field, Input } from "@/components/ui/form";
import { Table, TableWrap, Td, Th } from "@/components/ui/table";
import { type Group, api, queries, usePolicyMutation } from "@/lib/api/hooks";

function GroupDialog({ open, group, onClose }: { open: boolean; group?: Group; onClose: () => void }) {
  const [id, setId] = useState("");
  const [description, setDescription] = useState("");
  useEffect(() => {
    if (open) {
      setId(group?.id ?? "");
      setDescription(group?.description ?? "");
    }
  }, [open, group]);

  const save = usePolicyMutation(
    () => (group ? api.updateGroup(group.id, { description }) : api.createGroup({ id, description })),
    group ? "Group updated" : "Group added",
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
      title={group ? `Edit ${group.id}` : "Add group"}
      description="Groups let rules and sources apply to several clients at once."
    >
      <form className="space-y-4" onSubmit={submit}>
        <Field label="Name" htmlFor="group-id">
          <Input
            id="group-id"
            required
            autoComplete="off"
            disabled={group !== undefined}
            placeholder="kids"
            value={id}
            onChange={(event) => setId(event.target.value)}
          />
        </Field>
        <Field label="Description (optional)" htmlFor="group-description">
          <Input
            id="group-description"
            autoComplete="off"
            value={description}
            onChange={(event) => setDescription(event.target.value)}
          />
        </Field>
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" disabled={save.isPending}>
            Save group
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

export function GroupsPage({ readOnly }: { readOnly: boolean }) {
  const groups = useQuery(queries.groups());
  const [dialogOpen, setDialogOpen] = useState(false);
  const [selected, setSelected] = useState<Group>();
  const [deleting, setDeleting] = useState<Group>();
  const remove = usePolicyMutation((group: Group) => api.deleteGroup(group.id), "Group deleted");

  function open(group?: Group) {
    setSelected(group);
    setDialogOpen(true);
  }

  return (
    <>
      <PageHeader
        title="Groups"
        description="Apply rules and sources to several clients at once."
        actions={
          <Button variant="primary" disabled={readOnly} onClick={() => open()}>
            <Plus aria-hidden className="size-4" />
            Add group
          </Button>
        }
      />
      {readOnly && <ReadOnlyNotice />}
      <Card>
        {groups.isPending && <Loading />}
        {groups.isError && <ErrorState error={groups.error} onRetry={() => void groups.refetch()} />}
        {groups.data?.length === 0 && <Empty title="No groups yet">Add a group, then put clients in it.</Empty>}
        {groups.data && groups.data.length > 0 && (
          <TableWrap>
            <Table>
              <thead>
                <tr>
                  <Th>Group</Th>
                  <Th>Description</Th>
                  <Th className="text-right">Clients</Th>
                  <Th className="text-right">Rules</Th>
                  <Th className="text-right">Sources</Th>
                  <Th>
                    <span className="sr-only">Actions</span>
                  </Th>
                </tr>
              </thead>
              <tbody>
                {groups.data.map((group) => (
                  <tr key={group.id}>
                    <Td className="font-medium">{group.id}</Td>
                    <Td className="text-text-secondary">{group.description ?? "None"}</Td>
                    <Td className="text-right">{group.client_count}</Td>
                    <Td className="text-right">{group.rule_count}</Td>
                    <Td className="text-right">{group.list_count}</Td>
                    <Td className="whitespace-nowrap text-right">
                      <Button
                        variant="ghost"
                        size="icon"
                        disabled={readOnly}
                        aria-label={`Edit ${group.id}`}
                        onClick={() => open(group)}
                      >
                        <Pencil aria-hidden className="size-4" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon"
                        disabled={readOnly}
                        aria-label={`Delete ${group.id}`}
                        onClick={() => setDeleting(group)}
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
      <GroupDialog open={dialogOpen} group={selected} onClose={() => setDialogOpen(false)} />
      <ConfirmDialog
        open={deleting !== undefined}
        onOpenChange={(next) => {
          if (!next) setDeleting(undefined);
        }}
        title={`Delete ${deleting?.id ?? "this group"}?`}
        description="Groups still used by clients, rules or sources can't be deleted."
        confirmLabel="Delete group"
        pending={remove.isPending}
        onConfirm={() => {
          if (deleting) remove.mutate(deleting, { onSettled: () => setDeleting(undefined) });
        }}
      />
    </>
  );
}
