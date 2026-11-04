import { useQuery, useQueryClient } from "@tanstack/react-query";
import { type ReactNode, useRef, useState } from "react";
import { toast } from "sonner";

import { ErrorState, Loading, PageHeader, ReadOnlyNotice } from "@/components/states";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardHeader } from "@/components/ui/card";
import { ConfirmDialog } from "@/components/ui/dialog";
import { Table, TableWrap, Td, Th } from "@/components/ui/table";
import { type Schemas, downloadBackup, errorMessage, uploadBackup } from "@/lib/api/client";
import { api, queries, usePolicyMutation } from "@/lib/api/hooks";
import { formatBytes, formatCount, formatDateTime, formatSeconds, shortRevision } from "@/lib/format";

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex justify-between gap-4 border-t border-border px-4 py-2 text-sm">
      <dt className="text-text-muted">{label}</dt>
      <dd className="text-right break-words">{children}</dd>
    </div>
  );
}

const ACTION_LABELS: Record<string, string> = {
  "auth.setup": "Set up the node",
  "auth.login_failed": "Failed sign-in",
  "auth.password_changed": "Changed password",
  "rule.create": "Added a rule",
  "rule.update": "Changed a rule",
  "rule.delete": "Deleted a rule",
  "list.create": "Added a source",
  "list.update": "Changed a source",
  "list.delete": "Removed a source",
  "client.create": "Named a client",
  "client.update": "Changed a client",
  "client.delete": "Removed a client",
  "group.create": "Added a group",
  "group.update": "Changed a group",
  "group.delete": "Deleted a group",
  "settings.update": "Changed settings",
  "config.activate": "Restored a revision",
  "zone.create": "Added a local zone",
  "zone.delete": "Removed a local zone",
  "record.create": "Added a local record",
  "record.update": "Changed a local record",
  "record.delete": "Deleted a local record",
  "cache.flush": "Flushed the cache",
  "backup.create": "Downloaded a backup",
  "backup.restore": "Restored a backup",
};

function BackupCard({ readOnly }: { readOnly: boolean }) {
  const [file, setFile] = useState<File>();
  const [preview, setPreview] = useState<Schemas["RestoreResult"]>();
  const [pending, setPending] = useState(false);
  const client = useQueryClient();
  const input = useRef<HTMLInputElement>(null);

  function reset() {
    setFile(undefined);
    setPreview(undefined);
    if (input.current) input.current.value = "";
  }

  async function download() {
    setPending(true);
    try {
      const { blob, fileName } = await downloadBackup();
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = fileName;
      link.click();
      URL.revokeObjectURL(url);
      toast.success("Backup downloaded");
    } catch (error) {
      toast.error(errorMessage(error));
    } finally {
      setPending(false);
    }
  }

  async function check(chosen: File) {
    setFile(chosen);
    setPreview(undefined);
    setPending(true);
    try {
      setPreview(await uploadBackup(chosen, true));
    } catch (error) {
      toast.error(errorMessage(error));
      reset();
    } finally {
      setPending(false);
    }
  }

  async function restore() {
    if (!file) return;
    setPending(true);
    try {
      await uploadBackup(file, false);
      await client.invalidateQueries();
      toast.success("Backup restored and active");
      reset();
    } catch (error) {
      toast.error(errorMessage(error));
    } finally {
      setPending(false);
    }
  }

  return (
    <Card className="mt-4">
      <CardHeader
        title="Backup and restore"
        description="Backups hold your policy, lists and change history. Accounts and query logs are left out."
      />
      <div className="flex flex-wrap items-center gap-3 px-4 pb-4">
        <Button disabled={pending} onClick={() => void download()}>
          Download backup
        </Button>
        <div>
          <label htmlFor="restore-file" className="sr-only">
            Backup file to restore
          </label>
          <input
            ref={input}
            id="restore-file"
            type="file"
            accept=".gz,application/gzip"
            disabled={readOnly || pending}
            className="text-sm text-text-secondary file:mr-3 file:h-9 file:cursor-pointer file:rounded-md file:border file:border-border-strong file:bg-surface file:px-3 file:text-sm file:font-medium file:text-text"
            onChange={(event) => {
              const chosen = event.target.files?.[0];
              if (chosen) void check(chosen);
            }}
          />
        </div>
      </div>
      {preview && (
        <div role="status" className="mx-4 mb-4 rounded-md bg-surface-muted p-3 text-sm">
          <p className="font-medium">This backup is valid.</p>
          <p className="mt-1 text-text-secondary">
            From {formatDateTime(preview.created_at)}, version {preview.app_version}: {preview.rule_count} rules,{" "}
            {preview.list_count} sources, {preview.client_count} clients and {preview.local_record_count} local
            records. Restoring replaces the active policy right away, and the current one stays in history.
          </p>
          {preview.has_credentials && (
            <p className="mt-1 text-text-secondary">
              It also holds encrypted accounts, which only <code>fx backup restore</code> can restore.
            </p>
          )}
          <div className="mt-3 flex gap-2">
            <Button variant="danger" size="sm" disabled={pending} onClick={() => void restore()}>
              Restore this backup
            </Button>
            <Button size="sm" disabled={pending} onClick={reset}>
              Cancel
            </Button>
          </div>
        </div>
      )}
    </Card>
  );
}

export function SystemPage({ readOnly }: { readOnly: boolean }) {
  const system = useQuery(queries.system());
  const revisions = useQuery(queries.revisions());
  const audit = useQuery(queries.audit());
  const [restoring, setRestoring] = useState<string>();
  const activate = usePolicyMutation(
    (revision: string) => api.activateRevision(revision),
    "Revision restored and active",
  );
  const data = system.data;

  return (
    <>
      <PageHeader title="System" description="Node health, policy history and recent changes." />
      {readOnly && <ReadOnlyNotice />}
      {system.isPending && <Loading />}
      {system.isError && <ErrorState error={system.error} onRetry={() => void system.refetch()} />}
      {data && (
        <div className="grid gap-4 lg:grid-cols-2">
          <Card>
            <CardHeader title="Node" />
            <dl>
              <Row label="Version">{data.version}</Row>
              <Row label="Running for">{formatSeconds(data.uptime_seconds)}</Row>
              <Row label="DNS listeners">{data.dns_listeners.join(", ")}</Row>
              <Row label="DNSSEC validation">{data.dnssec_validation ? "On" : "Off"}</Row>
              <Row label="Active policy">
                <code className="text-xs">{shortRevision(data.policy_revision)}</code>
              </Row>
              <Row label="Rules, sources, clients">
                {data.rule_count}, {data.list_count}, {data.client_count}
              </Row>
            </dl>
          </Card>
          <Card>
            <CardHeader
              title="Query data"
              actions={
                data.telemetry_available ? (
                  <Badge tone="success">Available</Badge>
                ) : (
                  <Badge tone="error">Unavailable</Badge>
                )
              }
            />
            <dl>
              <Row label="Recorded since start">{formatCount(data.queries_recorded)}</Row>
              <Row label="Dropped events">{formatCount(data.events_dropped)}</Row>
              <Row label="Write errors">{formatCount(data.telemetry_write_errors)}</Row>
              <Row label="History on disk">{formatBytes(data.query_history_bytes)}</Row>
              <Row label="History goes back">
                {data.query_history_retained_seconds > 0
                  ? formatSeconds(data.query_history_retained_seconds)
                  : "No history yet"}
              </Row>
            </dl>
          </Card>
          {data.policy_warnings.length > 0 && (
            <Card className="lg:col-span-2">
              <CardHeader
                title="Policy warnings"
                description="These don't stop the policy working, but may not be what you meant."
              />
              <ul className="list-disc space-y-1 px-8 pb-4 text-sm text-text-secondary">
                {data.policy_warnings.map((warning) => (
                  <li key={warning}>{warning}</li>
                ))}
              </ul>
            </Card>
          )}
        </div>
      )}

      <BackupCard readOnly={readOnly} />

      <Card className="mt-4">
        <CardHeader
          title="Policy history"
          description="The node keeps its last three good policies, and can return to any of them."
        />
        {revisions.isPending && <Loading />}
        {revisions.isError && <ErrorState error={revisions.error} onRetry={() => void revisions.refetch()} />}
        {revisions.data?.length === 0 && (
          <p className="px-4 pb-4 text-sm text-text-muted">No changes have been saved yet.</p>
        )}
        {revisions.data && revisions.data.length > 0 && (
          <TableWrap>
            <Table>
              <thead>
                <tr>
                  <Th>Revision</Th>
                  <Th className="text-right">Rules</Th>
                  <Th className="text-right">Sources</Th>
                  <Th className="text-right">Clients</Th>
                  <Th>
                    <span className="sr-only">Actions</span>
                  </Th>
                </tr>
              </thead>
              <tbody>
                {revisions.data.map((revision) => (
                  <tr key={revision.revision}>
                    <Td>
                      <code className="text-xs">{shortRevision(revision.revision)}</code>
                    </Td>
                    <Td className="text-right">{revision.rule_count}</Td>
                    <Td className="text-right">{revision.list_count}</Td>
                    <Td className="text-right">{revision.client_count}</Td>
                    <Td className="text-right">
                      {revision.active ? (
                        <Badge tone="success">Active</Badge>
                      ) : (
                        <Button size="sm" disabled={readOnly} onClick={() => setRestoring(revision.revision)}>
                          Restore
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

      <Card className="mt-4">
        <CardHeader title="Recent changes" description="Who changed what on this node." />
        {audit.isPending && <Loading />}
        {audit.isError && <ErrorState error={audit.error} onRetry={() => void audit.refetch()} />}
        {audit.data && (
          <TableWrap className="max-h-96 overflow-y-auto">
            <Table>
              <thead>
                <tr>
                  <Th>When</Th>
                  <Th>Who</Th>
                  <Th>What</Th>
                  <Th>Target</Th>
                </tr>
              </thead>
              <tbody>
                {audit.data.map((event) => (
                  <tr key={event.id}>
                    <Td className="whitespace-nowrap text-text-secondary">{formatDateTime(event.occurred_at)}</Td>
                    <Td>{event.actor}</Td>
                    <Td>{ACTION_LABELS[event.action] ?? event.action}</Td>
                    <Td className="max-w-64 truncate text-text-secondary" title={event.target}>
                      {event.target}
                    </Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          </TableWrap>
        )}
      </Card>

      <ConfirmDialog
        open={restoring !== undefined}
        onOpenChange={(open) => {
          if (!open) setRestoring(undefined);
        }}
        title="Restore this revision?"
        description="Rules, sources and clients return to how they were in that revision, right away. This is saved as a new change."
        confirmLabel="Restore revision"
        pending={activate.isPending}
        onConfirm={() => {
          if (restoring) activate.mutate(restoring, { onSettled: () => setRestoring(undefined) });
        }}
      />
    </>
  );
}
