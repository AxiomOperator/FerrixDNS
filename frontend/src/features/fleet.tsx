import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { type FormEvent, useState } from "react";
import { toast } from "sonner";

import { Empty, ErrorState, Loading, PageHeader } from "@/components/states";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardHeader } from "@/components/ui/card";
import { ConfirmDialog, Dialog } from "@/components/ui/dialog";
import { Field, Input, Select } from "@/components/ui/form";
import { Table, TableWrap, Td, Th } from "@/components/ui/table";
import { useChooseSite } from "@/features/site-context";
import { AuditCard } from "@/features/system";
import { type Schemas } from "@/lib/api/client";
import { type Deployment, type FleetNode, type Site, api, queries, usePolicyMutation } from "@/lib/api/hooks";
import { formatCount, formatDateTime, formatDuration, formatSeconds, shortRevision, timeAgo } from "@/lib/format";

// --- Adding nodes ---

function CopyBlock({ label, text }: { label: string; text: string }) {
  return (
    <div>
      <div className="mb-1 flex items-center justify-between gap-2">
        <p className="text-sm font-medium">{label}</p>
        <Button
          size="sm"
          onClick={() => {
            void navigator.clipboard
              .writeText(text)
              .then(() => toast.success("Copied"))
              .catch(() => toast.error("Your browser didn't allow copying. Select the text instead."));
          }}
        >
          Copy
        </Button>
      </div>
      <pre className="overflow-x-auto rounded-md bg-surface-muted p-3 text-xs break-all whitespace-pre-wrap" tabIndex={0}>
        {text}
      </pre>
    </div>
  );
}

function AddNodeDialog({
  open,
  sites,
  initialSite,
  onClose,
}: {
  open: boolean;
  sites: Site[];
  initialSite?: string;
  onClose: () => void;
}) {
  const [site, setSite] = useState(initialSite ?? "");
  const [minutes, setMinutes] = useState(60);
  const [created, setCreated] = useState<Schemas["EnrollmentTokenCreated"]>();
  const create = usePolicyMutation((siteId: string) =>
    api.createEnrollmentToken({ site_id: siteId, ttl_minutes: minutes }),
  );
  const chosen = site || initialSite || sites[0]?.id || "";

  function close() {
    setCreated(undefined);
    onClose();
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!next) close();
      }}
      title="Add a node"
      description="A token lets one new node join, once. It's only shown here, so treat it like a password."
    >
      {created ? (
        <div className="space-y-4">
          <CopyBlock label="Enrollment token" text={created.token} />
          <CopyBlock
            label="Run this on the new server, from a copy of this repository"
            text={`sudo FERRIXDNS_ENROLL_TOKEN=${created.token} scripts/docker-deploy.sh --node-only --address <this server's address>`}
          />
          <p className="text-xs text-text-muted">
            It works until {formatDateTime(created.expires_at)}. The node needs to reach{" "}
            {created.controller_url}. It serves DNS with no dashboard, and appears under Nodes once it joins.
          </p>
          <div className="flex justify-end">
            <Button variant="primary" onClick={close}>
              Done
            </Button>
          </div>
        </div>
      ) : (
        <form
          className="space-y-4"
          onSubmit={(event: FormEvent) => {
            event.preventDefault();
            create.mutate(chosen, { onSuccess: setCreated });
          }}
        >
          <Field label="Site" htmlFor="token-site">
            <Select id="token-site" value={chosen} onChange={(event) => setSite(event.target.value)}>
              {sites.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.name}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="Token works for" htmlFor="token-ttl" hint="Allow long enough for the image to build on the new server.">
            <Select id="token-ttl" value={minutes} onChange={(event) => setMinutes(Number(event.target.value))}>
              <option value={10}>10 minutes</option>
              <option value={60}>1 hour</option>
              <option value={1440}>1 day</option>
            </Select>
          </Field>
          <div className="flex justify-end gap-2">
            <Button onClick={close}>Cancel</Button>
            <Button type="submit" variant="primary" disabled={create.isPending || !chosen}>
              Create token
            </Button>
          </div>
        </form>
      )}
    </Dialog>
  );
}

// --- Sites ---

function SiteDialog({ open, sites, onClose }: { open: boolean; sites: Site[]; onClose: () => void }) {
  const [name, setName] = useState("");
  const [copyFrom, setCopyFrom] = useState("");
  const create = usePolicyMutation(
    () => api.createSite({ name, copy_from: copyFrom || undefined }),
    "Site added",
  );
  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!next) onClose();
      }}
      title="Add a site"
      description="A site is a group of nodes that enforce the same policy."
    >
      <form
        className="space-y-4"
        onSubmit={(event: FormEvent) => {
          event.preventDefault();
          create.mutate(undefined, {
            onSuccess: () => {
              setName("");
              setCopyFrom("");
              onClose();
            },
          });
        }}
      >
        <Field label="Name" htmlFor="site-name">
          <Input id="site-name" required autoComplete="off" value={name} onChange={(event) => setName(event.target.value)} />
        </Field>
        {sites.length > 0 && (
          <Field label="Start from" htmlFor="site-copy">
            <Select id="site-copy" value={copyFrom} onChange={(event) => setCopyFrom(event.target.value)}>
              <option value="">An empty policy</option>
              {sites.map((item) => (
                <option key={item.id} value={item.id}>
                  A copy of {item.name}
                </option>
              ))}
            </Select>
          </Field>
        )}
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" disabled={create.isPending}>
            Add site
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

function DeployDialog({ site, onClose }: { site: Site | undefined; onClose: () => void }) {
  const [strategy, setStrategy] = useState<"all" | "canary">("all");
  const [reason, setReason] = useState("");
  const deploy = usePolicyMutation(
    (siteId: string) => api.deploy({ site_id: siteId, strategy, reason: reason || undefined }),
    (result) => `Generation ${result.generation} is on its way`,
  );
  return (
    <Dialog
      open={site !== undefined}
      onOpenChange={(next) => {
        if (!next) onClose();
      }}
      title={`Deploy ${site?.name ?? ""}`}
      description="Sends this site's current policy to its nodes. Each node checks it, applies it and checks its DNS still answers, or goes back."
    >
      <form
        className="space-y-4"
        onSubmit={(event: FormEvent) => {
          event.preventDefault();
          if (site) {
            deploy.mutate(site.id, {
              onSuccess: () => {
                setReason("");
                onClose();
              },
            });
          }
        }}
      >
        <Field label="How" htmlFor="deploy-strategy">
          <Select
            id="deploy-strategy"
            value={strategy}
            onChange={(event) => setStrategy(event.target.value as "all" | "canary")}
          >
            <option value="all">All nodes at once</option>
            <option value="canary">One node first, then the rest if it's healthy</option>
          </Select>
        </Field>
        <Field label="Reason (optional)" htmlFor="deploy-reason">
          <Input id="deploy-reason" autoComplete="off" value={reason} onChange={(event) => setReason(event.target.value)} />
        </Field>
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" disabled={deploy.isPending}>
            Deploy
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

export function SitesPage() {
  const sites = useQuery(queries.sites());
  const navigate = useNavigate();
  const choose = useChooseSite();
  const [adding, setAdding] = useState(false);
  const [deploying, setDeploying] = useState<Site>();
  const [addingNodeTo, setAddingNodeTo] = useState<Site>();
  const [deleting, setDeleting] = useState<Site>();
  const remove = usePolicyMutation((id: string) => api.deleteSite(id), "Site removed");
  const update = usePolicyMutation(
    ({ id, auto }: { id: string; auto: boolean }) => api.updateSite(id, { auto_deploy_lists: auto }),
  );

  return (
    <>
      <PageHeader
        title="Sites"
        description="Each site has its own policy, and its nodes all enforce it."
        actions={
          <Button variant="primary" onClick={() => setAdding(true)}>
            Add site
          </Button>
        }
      />
      <Card>
        {sites.isPending && <Loading />}
        {sites.isError && <ErrorState error={sites.error} onRetry={() => void sites.refetch()} />}
        {sites.data?.length === 0 && <Empty title="No sites yet">Add one to give nodes a policy to enforce.</Empty>}
        {sites.data && sites.data.length > 0 && (
          <TableWrap>
            <Table>
              <thead>
                <tr>
                  <Th>Site</Th>
                  <Th className="text-right">Nodes online</Th>
                  <Th className="text-right">Rules</Th>
                  <Th className="text-right">Sources</Th>
                  <Th>Policy</Th>
                  <Th>List updates</Th>
                  <Th className="text-right">Actions</Th>
                </tr>
              </thead>
              <tbody>
                {sites.data.map((site) => (
                  <tr key={site.id}>
                    <Td className="font-medium">{site.name}</Td>
                    <Td className="text-right">
                      {site.nodes_online} of {site.node_count}
                    </Td>
                    <Td className="text-right">{formatCount(site.rule_count)}</Td>
                    <Td className="text-right">{formatCount(site.list_count)}</Td>
                    <Td>
                      {site.has_undeployed_changes ? (
                        <Badge tone="warning">Not deployed</Badge>
                      ) : site.deployed_generation ? (
                        <Badge tone="success">Generation {site.deployed_generation}</Badge>
                      ) : (
                        <Badge>Nothing to deploy</Badge>
                      )}
                    </Td>
                    <Td>
                      <label className="flex items-center gap-1.5 text-xs text-text-secondary">
                        <input
                          type="checkbox"
                          checked={site.auto_deploy_lists}
                          onChange={(event) => update.mutate({ id: site.id, auto: event.target.checked })}
                        />
                        Deploy by themselves
                      </label>
                    </Td>
                    <Td>
                      <div className="flex flex-wrap justify-end gap-1.5">
                        <Button
                          size="sm"
                          onClick={() => {
                            choose(site.id);
                            void navigate({ to: "/filtering/rules" });
                          }}
                        >
                          Edit policy
                        </Button>
                        <Button size="sm" onClick={() => setAddingNodeTo(site)}>
                          Add node
                        </Button>
                        <Button size="sm" variant="primary" onClick={() => setDeploying(site)}>
                          Deploy
                        </Button>
                        <Button size="sm" variant="ghost" disabled={site.node_count > 0} onClick={() => setDeleting(site)}>
                          Remove
                        </Button>
                      </div>
                    </Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          </TableWrap>
        )}
      </Card>
      <SiteDialog open={adding} sites={sites.data ?? []} onClose={() => setAdding(false)} />
      <DeployDialog site={deploying} onClose={() => setDeploying(undefined)} />
      <AddNodeDialog
        key={addingNodeTo?.id ?? "none"}
        open={addingNodeTo !== undefined}
        sites={sites.data ?? []}
        initialSite={addingNodeTo?.id}
        onClose={() => setAddingNodeTo(undefined)}
      />
      <ConfirmDialog
        open={deleting !== undefined}
        onOpenChange={(open) => {
          if (!open) setDeleting(undefined);
        }}
        title={`Remove ${deleting?.name ?? "this site"}?`}
        description="Its policy and deployment history are deleted. This can't be undone."
        confirmLabel="Remove site"
        pending={remove.isPending}
        onConfirm={() => {
          if (deleting) remove.mutate(deleting.id, { onSettled: () => setDeleting(undefined) });
        }}
      />
    </>
  );
}

// --- Nodes ---

function cacheHitRate(node: FleetNode): string {
  const lookups = node.cache_hits + node.cache_misses;
  return lookups > 0 ? `${((node.cache_hits / lookups) * 100).toFixed(0)}%` : "No data";
}

function NodeStatus({ node }: { node: FleetNode }) {
  if (!node.online) return <Badge tone="error">Offline</Badge>;
  if (node.desired_generation && node.applied_generation < node.desired_generation) {
    return <Badge tone="warning">Updating</Badge>;
  }
  return <Badge tone="success">Online</Badge>;
}

function NodeDetail({ node, onClose }: { node: FleetNode | undefined; onClose: () => void }) {
  return (
    <Dialog
      side
      open={node !== undefined}
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
      title={node?.name ?? "Node"}
      description={node ? `In ${node.site_name}` : undefined}
    >
      {node && (
        <div className="space-y-4 text-sm">
          <dl className="space-y-1.5">
            <Row label="Last report">{node.last_seen ? timeAgo(node.last_seen) : "Never"}</Row>
            <Row label="Version">{node.version || "Unknown"}</Row>
            <Row label="Running for">{formatSeconds(node.uptime_seconds)}</Row>
            <Row label="Listening on">{node.listeners.join(", ") || "Unknown"}</Row>
            <Row label="Policy revision">{node.policy_revision ? shortRevision(node.policy_revision) : "None"}</Row>
            <Row label="Blocking">{node.blocking_paused ? "Paused" : "On"}</Row>
            <Row label="Cache hit rate">{cacheHitRate(node)}</Row>
            <Row label="Cached answers">{formatCount(node.cache_entries)}</Row>
            <Row label="Refreshed early">{formatCount(node.cache_prefetches)}</Row>
            <Row label="Expired answers used">{formatCount(node.cache_stale_served)}</Row>
          </dl>
          <div>
            <h3 className="mb-1 font-semibold">Upstream servers</h3>
            {node.upstreams.length === 0 ? (
              <p className="text-text-muted">None reported.</p>
            ) : (
              <TableWrap>
                <Table>
                  <thead>
                    <tr>
                      <Th>Server</Th>
                      <Th className="text-right">Answers</Th>
                      <Th className="text-right">Failures</Th>
                      <Th className="text-right">Last</Th>
                    </tr>
                  </thead>
                  <tbody>
                    {node.upstreams.map((upstream) => (
                      <tr key={upstream.server}>
                        <Td className="break-all">{upstream.server}</Td>
                        <Td className="text-right">{formatCount(upstream.responses)}</Td>
                        <Td className="text-right">{formatCount(upstream.failures)}</Td>
                        <Td className="text-right">{formatDuration(upstream.last_latency_us)}</Td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
              </TableWrap>
            )}
          </div>
        </div>
      )}
    </Dialog>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex justify-between gap-4">
      <dt className="text-text-muted">{label}</dt>
      <dd className="text-right break-words">{children}</dd>
    </div>
  );
}

export function NodesPage() {
  const nodes = useQuery(queries.fleetNodes());
  const sites = useQuery(queries.sites());
  const tokens = useQuery(queries.enrollmentTokens());
  const [adding, setAdding] = useState(false);
  const [selected, setSelected] = useState<string>();
  const [removing, setRemoving] = useState<FleetNode>();
  const [renaming, setRenaming] = useState<FleetNode>();
  const [name, setName] = useState("");
  const remove = usePolicyMutation((id: string) => api.removeNode(id), "Node removed");
  const rename = usePolicyMutation(
    ({ id, value }: { id: string; value: string }) => api.renameNode(id, { name: value }),
    "Node renamed",
  );
  const cancel = usePolicyMutation((id: string) => api.deleteEnrollmentToken(id), "Token cancelled");
  const hasSites = (sites.data?.length ?? 0) > 0;

  return (
    <>
      <PageHeader
        title="Nodes"
        description="The servers answering DNS. They connect out to this controller, and keep serving if they can't reach it."
        actions={
          <Button variant="primary" disabled={!hasSites} onClick={() => setAdding(true)}>
            Add node
          </Button>
        }
      />
      <Card>
        {nodes.isPending && <Loading />}
        {nodes.isError && <ErrorState error={nodes.error} onRetry={() => void nodes.refetch()} />}
        {nodes.data?.length === 0 && (
          <Empty title="No nodes yet">{hasSites ? "Add one to start." : "Add a site first, under Sites."}</Empty>
        )}
        {nodes.data && nodes.data.length > 0 && (
          <TableWrap>
            <Table>
              <thead>
                <tr>
                  <Th>Node</Th>
                  <Th>Site</Th>
                  <Th>Status</Th>
                  <Th>Generation</Th>
                  <Th className="text-right">Queries, last hour</Th>
                  <Th className="text-right">Blocked</Th>
                  <Th className="text-right">Cache hit rate</Th>
                  <Th>Last report</Th>
                  <Th className="text-right">Actions</Th>
                </tr>
              </thead>
              <tbody>
                {nodes.data.map((node) => (
                  <tr key={node.id}>
                    <Td className="font-medium">{node.name}</Td>
                    <Td>{node.site_name}</Td>
                    <Td>
                      <NodeStatus node={node} />
                    </Td>
                    <Td>
                      {node.applied_generation}
                      {node.desired_generation && node.desired_generation !== node.applied_generation
                        ? ` of ${node.desired_generation}`
                        : ""}
                    </Td>
                    <Td className="text-right">{formatCount(node.queries_last_hour)}</Td>
                    <Td className="text-right">{formatCount(node.blocked_last_hour)}</Td>
                    <Td className="text-right">{cacheHitRate(node)}</Td>
                    <Td>{node.last_seen ? timeAgo(node.last_seen) : "Never"}</Td>
                    <Td>
                      <div className="flex justify-end gap-1.5">
                        <Button size="sm" aria-label={`Details for ${node.name}`} onClick={() => setSelected(node.id)}>
                          Details
                        </Button>
                        <Button
                          size="sm"
                          aria-label={`Rename ${node.name}`}
                          onClick={() => {
                            setName(node.name);
                            setRenaming(node);
                          }}
                        >
                          Rename
                        </Button>
                        <Button size="sm" variant="ghost" aria-label={`Remove ${node.name}`} onClick={() => setRemoving(node)}>
                          Remove
                        </Button>
                      </div>
                    </Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          </TableWrap>
        )}
      </Card>
      {tokens.data && tokens.data.length > 0 && (
        <Card className="mt-4">
          <CardHeader title="Tokens waiting to be used" description="Each lets one new node join." />
          <TableWrap>
            <Table>
              <thead>
                <tr>
                  <Th>Site</Th>
                  <Th>Created by</Th>
                  <Th>Works until</Th>
                  <Th className="text-right">Actions</Th>
                </tr>
              </thead>
              <tbody>
                {tokens.data.map((token) => (
                  <tr key={token.id}>
                    <Td>{token.site_name}</Td>
                    <Td>{token.created_by}</Td>
                    <Td>{formatDateTime(token.expires_at)}</Td>
                    <Td className="text-right">
                      <Button size="sm" variant="ghost" disabled={cancel.isPending} onClick={() => cancel.mutate(token.id)}>
                        Cancel
                      </Button>
                    </Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          </TableWrap>
        </Card>
      )}
      <AddNodeDialog open={adding} sites={sites.data ?? []} onClose={() => setAdding(false)} />
      <NodeDetail node={nodes.data?.find((node) => node.id === selected)} onClose={() => setSelected(undefined)} />
      <Dialog
        open={renaming !== undefined}
        onOpenChange={(open) => {
          if (!open) setRenaming(undefined);
        }}
        title="Rename node"
      >
        <form
          className="space-y-4"
          onSubmit={(event: FormEvent) => {
            event.preventDefault();
            if (renaming) {
              rename.mutate({ id: renaming.id, value: name }, { onSuccess: () => setRenaming(undefined) });
            }
          }}
        >
          <Field label="Name" htmlFor="node-name">
            <Input id="node-name" required autoComplete="off" value={name} onChange={(event) => setName(event.target.value)} />
          </Field>
          <div className="flex justify-end gap-2">
            <Button onClick={() => setRenaming(undefined)}>Cancel</Button>
            <Button type="submit" variant="primary" disabled={rename.isPending}>
              Save
            </Button>
          </div>
        </form>
      </Dialog>
      <ConfirmDialog
        open={removing !== undefined}
        onOpenChange={(open) => {
          if (!open) setRemoving(undefined);
        }}
        title={`Remove ${removing?.name ?? "this node"}?`}
        description="It stops being able to reach this controller, and keeps serving DNS with the last policy it applied. To bring it back, it needs a new token."
        confirmLabel="Remove node"
        pending={remove.isPending}
        onConfirm={() => {
          if (removing) remove.mutate(removing.id, { onSettled: () => setRemoving(undefined) });
        }}
      />
    </>
  );
}

// --- Deployments ---

const STATUS: Record<string, { tone: "success" | "warning" | "error" | "neutral"; label: string }> = {
  canary: { tone: "warning", label: "Trying on one node" },
  rolling_out: { tone: "warning", label: "Rolling out" },
  succeeded: { tone: "success", label: "Succeeded" },
  partially_failed: { tone: "error", label: "Partly failed" },
  failed: { tone: "error", label: "Failed" },
  superseded: { tone: "neutral", label: "Replaced by a newer one" },
};

const KIND: Record<string, string> = {
  policy: "Policy change",
  list_refresh: "List update",
  rollback: "Rollback",
};

const NODE_STATE: Record<string, { tone: "success" | "warning" | "error" | "neutral"; label: string }> = {
  pending: { tone: "neutral", label: "Waiting" },
  downloading: { tone: "warning", label: "Downloading" },
  staged: { tone: "warning", label: "Downloaded" },
  activating: { tone: "warning", label: "Applying" },
  healthy: { tone: "success", label: "Healthy" },
  failed: { tone: "error", label: "Failed" },
  reverted: { tone: "error", label: "Went back" },
};

function DeploymentCard({
  deployment,
  onRollback,
  onPromote,
}: {
  deployment: Deployment;
  onRollback: () => void;
  onPromote: () => void;
}) {
  const status = STATUS[deployment.status] ?? { tone: "neutral" as const, label: deployment.status };
  return (
    <Card>
      <CardHeader
        title={`${deployment.site_name}, generation ${deployment.generation}`}
        description={`${KIND[deployment.kind] ?? deployment.kind} by ${deployment.created_by}, ${formatDateTime(deployment.created_at)}${deployment.reason ? `. ${deployment.reason}` : ""}`}
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <Badge tone={status.tone}>{status.label}</Badge>
            {deployment.status === "canary" && (
              <Button size="sm" onClick={onPromote}>
                Send to all nodes now
              </Button>
            )}
            <Button size="sm" aria-label={`Go back to this, generation ${deployment.generation}`} onClick={onRollback}>
              Go back to this
            </Button>
          </div>
        }
      />
      {deployment.nodes.length === 0 ? (
        <p className="px-4 pb-4 text-sm text-text-muted">This site has no nodes yet. New nodes get this when they join.</p>
      ) : (
        <TableWrap>
          <Table>
            <thead>
              <tr>
                <Th>Node</Th>
                <Th>State</Th>
                <Th>Detail</Th>
              </tr>
            </thead>
            <tbody>
              {deployment.nodes.map((node) => {
                const state = NODE_STATE[node.state] ?? { tone: "neutral" as const, label: node.state };
                return (
                  <tr key={node.node_id}>
                    <Td className="font-medium">
                      {node.node_name}
                      {node.is_canary ? " (tried first)" : ""}
                    </Td>
                    <Td>
                      <Badge tone={state.tone}>{state.label}</Badge>
                    </Td>
                    <Td className="break-words text-text-secondary">
                      {node.detail ?? (node.online ? "" : "Offline. It catches up when it's back.")}
                    </Td>
                  </tr>
                );
              })}
            </tbody>
          </Table>
        </TableWrap>
      )}
    </Card>
  );
}

export function DeploymentsPage() {
  const deployments = useQuery(queries.deployments());
  const [target, setTarget] = useState<Deployment>();
  const rollback = usePolicyMutation(
    (id: string) => api.rollbackDeployment(id),
    (result) => `Going back, as generation ${result.generation}`,
  );
  const promote = usePolicyMutation((id: string) => api.promoteDeployment(id), "Sending to all nodes");

  return (
    <>
      <PageHeader title="Deployments" description="What was sent to which nodes, and how far each one has got." />
      {deployments.isPending && <Loading />}
      {deployments.isError && <ErrorState error={deployments.error} onRetry={() => void deployments.refetch()} />}
      {deployments.data?.length === 0 && (
        <Card>
          <Empty title="Nothing deployed yet">Deploy a site from the Sites page.</Empty>
        </Card>
      )}
      <div className="space-y-4">
        {deployments.data?.map((deployment) => (
          <DeploymentCard
            key={deployment.id}
            deployment={deployment}
            onRollback={() => setTarget(deployment)}
            onPromote={() => promote.mutate(deployment.id)}
          />
        ))}
      </div>
      <ConfirmDialog
        open={target !== undefined}
        onOpenChange={(open) => {
          if (!open) setTarget(undefined);
        }}
        title={`Go back to generation ${target?.generation ?? ""}?`}
        description="All of this site's nodes return to that policy, as a new deployment. The policy being edited isn't changed, so it then shows as not deployed."
        confirmLabel="Go back"
        pending={rollback.isPending}
        onConfirm={() => {
          if (target) rollback.mutate(target.id, { onSettled: () => setTarget(undefined) });
        }}
      />
    </>
  );
}

export function ActivityPage() {
  return (
    <>
      <PageHeader title="Activity" description="Who changed what, across every site and node." />
      <AuditCard description="Newest first." />
    </>
  );
}
