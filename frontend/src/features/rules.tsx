import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation, useQuery } from "@tanstack/react-query";
import { CircleAlert, Pencil, Plus, Trash2 } from "lucide-react";
import { useEffect, useState } from "react";
import { useForm } from "react-hook-form";
import { z } from "zod";

import { Empty, ErrorState, Loading, PageHeader, ReadOnlyNotice } from "@/components/states";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardHeader } from "@/components/ui/card";
import { ConfirmDialog, Dialog } from "@/components/ui/dialog";
import { Field, Input, Select } from "@/components/ui/form";
import { Switch } from "@/components/ui/switch";
import { Table, TableWrap, Td, Th } from "@/components/ui/table";
import { errorMessage } from "@/lib/api/client";
import { type Rule, type TestResult, api, queries, usePolicyMutation } from "@/lib/api/hooks";
import { formatDateTime } from "@/lib/format";

const schema = z
  .object({
    action: z.enum(["deny", "allow"]),
    match_type: z.enum(["exact", "suffix", "regex"]),
    pattern: z.string().trim().min(1, "Enter a domain or pattern"),
    scope_kind: z.enum(["global", "group", "client"]),
    scope_id: z.string(),
    emergency: z.boolean(),
    reason: z.string(),
    expires_at: z.string(),
  })
  .refine((value) => value.scope_kind === "global" || value.scope_id !== "", {
    path: ["scope_id"],
    message: "Choose who this applies to",
  })
  .refine((value) => !value.emergency || value.action === "deny", {
    path: ["emergency"],
    message: "Only block rules can be emergency rules",
  });

type FormValues = z.infer<typeof schema>;

function toLocalInput(iso: string | null | undefined): string {
  if (!iso) return "";
  const date = new Date(iso);
  const offset = date.getTimezoneOffset() * 60_000;
  return new Date(date.getTime() - offset).toISOString().slice(0, 16);
}

function defaults(rule?: Rule): FormValues {
  const kind = rule?.scope.kind;
  return {
    action: rule?.action ?? "deny",
    match_type: rule?.match_type ?? "suffix",
    pattern: rule?.pattern ?? "",
    scope_kind: kind === "group" || kind === "client" ? kind : "global",
    scope_id: rule?.scope.id ?? "",
    emergency: rule?.emergency ?? false,
    reason: rule?.reason ?? "",
    expires_at: toLocalInput(rule?.expires_at),
  };
}

function RuleDialog({
  open,
  rule,
  onClose,
}: {
  open: boolean;
  rule?: Rule;
  onClose: () => void;
}) {
  const groups = useQuery(queries.groups());
  const clients = useQuery(queries.clients());
  const form = useForm<FormValues>({ resolver: zodResolver(schema), defaultValues: defaults(rule) });
  const { register, handleSubmit, watch, reset, formState } = form;

  useEffect(() => {
    if (open) reset(defaults(rule));
  }, [open, rule, reset]);

  const save = usePolicyMutation(
    async (values: FormValues) => {
      const expires = values.expires_at ? new Date(values.expires_at).toISOString() : "";
      const common = {
        action: values.action,
        match_type: values.match_type,
        pattern: values.pattern,
        scope: {
          kind: values.scope_kind,
          id: values.scope_kind === "global" ? null : values.scope_id,
        },
        emergency: values.emergency,
        reason: values.reason,
        expires_at: expires,
      };
      return rule ? api.updateRule(rule, common) : api.createRule(common);
    },
    rule ? "Rule updated and active" : "Rule added and active",
  );

  const scopeKind = watch("scope_kind");
  const matchType = watch("match_type");
  const knownClients = clients.data?.filter((client) => client.known) ?? [];

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!next) onClose();
      }}
      title={rule ? "Edit rule" : "Add rule"}
      description="Changes apply on this node as soon as they're saved."
    >
      <form
        className="space-y-4"
        onSubmit={(event) =>
          void handleSubmit((values) => save.mutate(values, { onSuccess: onClose }))(event)
        }
      >
        <div className="grid grid-cols-2 gap-3">
          <Field label="Action" htmlFor="rule-action">
            <Select id="rule-action" {...register("action")}>
              <option value="deny">Block</option>
              <option value="allow">Allow</option>
            </Select>
          </Field>
          <Field label="Match" htmlFor="rule-match">
            <Select id="rule-match" {...register("match_type")}>
              <option value="suffix">Domain and subdomains</option>
              <option value="exact">Exact domain</option>
              <option value="regex">Regular expression</option>
            </Select>
          </Field>
        </div>
        <Field
          label={matchType === "regex" ? "Pattern" : "Domain"}
          htmlFor="rule-pattern"
          error={formState.errors.pattern?.message}
        >
          <Input
            id="rule-pattern"
            autoComplete="off"
            placeholder={matchType === "regex" ? "^ads?[0-9]*\\." : "ads.example.com"}
            {...register("pattern")}
          />
        </Field>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Applies to" htmlFor="rule-scope">
            <Select id="rule-scope" {...register("scope_kind")}>
              <option value="global">Everyone</option>
              <option value="group">A group</option>
              <option value="client">A client</option>
            </Select>
          </Field>
          {scopeKind !== "global" && (
            <Field
              label={scopeKind === "group" ? "Group" : "Client"}
              htmlFor="rule-scope-id"
              error={formState.errors.scope_id?.message}
            >
              <Select id="rule-scope-id" {...register("scope_id")}>
                <option value="">Choose…</option>
                {scopeKind === "group"
                  ? groups.data?.map((group) => (
                      <option key={group.id} value={group.id}>
                        {group.id}
                      </option>
                    ))
                  : knownClients.map((client) => (
                      <option key={client.id} value={client.id}>
                        {client.name ?? client.id}
                      </option>
                    ))}
              </Select>
            </Field>
          )}
        </div>
        <Field label="Reason (optional)" htmlFor="rule-reason">
          <Input id="rule-reason" autoComplete="off" {...register("reason")} />
        </Field>
        <Field
          label="Expires (optional)"
          htmlFor="rule-expires"
          hint="In your local time. The rule stops applying then."
        >
          <Input id="rule-expires" type="datetime-local" {...register("expires_at")} />
        </Field>
        <label className="flex items-start gap-2 text-sm">
          <input type="checkbox" className="mt-0.5 size-4" {...register("emergency")} />
          <span>
            <span className="font-medium">Emergency block</span>
            <span className="block text-xs text-text-muted">
              Beats every other rule, for everyone it applies to.
            </span>
          </span>
        </label>
        {formState.errors.emergency && (
          <p role="alert" className="text-xs font-medium text-danger">
            {formState.errors.emergency.message}
          </p>
        )}
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" disabled={save.isPending}>
            {rule ? "Save rule" : "Add rule"}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

const TIER_LABELS: Record<string, string> = {
  emergency_deny: "an emergency block",
  exact_allow: "an exact allow rule",
  suffix_allow: "a domain allow rule",
  regex_allow: "a regex allow rule",
  exact_deny: "an exact block rule",
  suffix_deny: "a domain block rule",
  subscribed_allow: "an allow list",
  subscribed_deny: "a block list",
  regex_deny: "a regex block rule",
  default_allow: "the default, because nothing matched",
};

function TestPanel() {
  const [domain, setDomain] = useState("");
  const [clientIp, setClientIp] = useState("");
  const [result, setResult] = useState<TestResult>();
  const test = useMutation({
    mutationFn: () => api.testRule({ domain, client_ip: clientIp || null }),
    onSuccess: setResult,
    onError: () => setResult(undefined),
  });

  return (
    <Card className="mb-4">
      <CardHeader
        title="Test a domain"
        description="See what the active policy would do, without sending a query."
      />
      <form
        className="grid gap-2 px-4 pb-4 sm:grid-cols-[1fr_14rem_auto]"
        onSubmit={(event) => {
          event.preventDefault();
          test.mutate();
        }}
      >
        <div>
          <label htmlFor="test-domain" className="sr-only">
            Domain
          </label>
          <Input
            id="test-domain"
            required
            placeholder="ads.example.com"
            value={domain}
            onChange={(event) => setDomain(event.target.value)}
          />
        </div>
        <div>
          <label htmlFor="test-client" className="sr-only">
            Client address (optional)
          </label>
          <Input
            id="test-client"
            placeholder="Client address (optional)"
            value={clientIp}
            onChange={(event) => setClientIp(event.target.value)}
          />
        </div>
        <Button type="submit" disabled={test.isPending}>
          Test
        </Button>
      </form>
      {test.isError && (
        <p role="alert" className="flex items-center gap-1.5 px-4 pb-4 text-sm font-medium text-danger">
          <CircleAlert aria-hidden className="size-4" />
          {errorMessage(test.error)}
        </p>
      )}
      {result && (
        <div role="status" className="flex flex-wrap items-center gap-2 px-4 pb-4 text-sm">
          <Badge tone={result.action === "deny" ? "danger" : "success"}>
            {result.action === "deny" ? "Blocked" : "Allowed"}
          </Badge>
          <span className="text-text-secondary">
            {result.normalized_domain} is decided by {TIER_LABELS[result.tier] ?? result.tier}
            {result.rule_pattern ? ` (${result.rule_pattern})` : ""}
            {result.list_name ? ` (${result.list_name})` : ""}
            {result.scope ? `, at ${result.scope} scope` : ""}.
          </span>
        </div>
      )}
    </Card>
  );
}

function scopeLabel(rule: Rule, clientNames: Map<string, string>): string {
  switch (rule.scope.kind) {
    case "global":
      return "Everyone";
    case "client":
      return `Client: ${clientNames.get(rule.scope.id ?? "") ?? rule.scope.id}`;
    case "group":
      return `Group: ${rule.scope.id}`;
    default:
      return `Site: ${rule.scope.id}`;
  }
}

const MATCH_LABELS = { exact: "Exact", suffix: "Domain + subdomains", regex: "Regex" };

export function RulesPage({ readOnly }: { readOnly: boolean }) {
  const rules = useQuery(queries.rules());
  const clients = useQuery(queries.clients());
  const [editing, setEditing] = useState<Rule>();
  const [adding, setAdding] = useState(false);
  const [deleting, setDeleting] = useState<Rule>();

  const toggle = usePolicyMutation((rule: Rule) => api.updateRule(rule, { enabled: !rule.enabled }));
  const remove = usePolicyMutation((rule: Rule) => api.deleteRule(rule), "Rule deleted");

  const clientNames = new Map(
    clients.data?.filter((client) => client.name).map((client) => [client.id, client.name ?? ""]),
  );

  return (
    <>
      <PageHeader
        title="Rules"
        description="The narrowest match wins: a client's rules beat its group's, which beat rules for everyone."
        actions={
          <Button variant="primary" disabled={readOnly} onClick={() => setAdding(true)}>
            <Plus aria-hidden className="size-4" />
            Add rule
          </Button>
        }
      />
      {readOnly && <ReadOnlyNotice />}
      <TestPanel />
      <Card>
        {rules.isPending && <Loading />}
        {rules.isError && <ErrorState error={rules.error} onRetry={() => void rules.refetch()} />}
        {rules.data?.length === 0 && (
          <Empty title="No rules yet">Add a rule to block or allow a domain on this node.</Empty>
        )}
        {rules.data && rules.data.length > 0 && (
          <TableWrap>
            <Table>
              <thead>
                <tr>
                  <Th>Action</Th>
                  <Th>Pattern</Th>
                  <Th>Match</Th>
                  <Th>Applies to</Th>
                  <Th>Expires</Th>
                  <Th>Enabled</Th>
                  <Th>
                    <span className="sr-only">Actions</span>
                  </Th>
                </tr>
              </thead>
              <tbody>
                {rules.data.map((rule) => (
                  <tr key={rule.id}>
                    <Td>
                      <span className="flex flex-wrap gap-1">
                        <Badge tone={rule.action === "deny" ? "danger" : "success"}>
                          {rule.action === "deny" ? "Block" : "Allow"}
                        </Badge>
                        {rule.emergency && <Badge tone="error">Emergency</Badge>}
                      </span>
                    </Td>
                    <Td className="max-w-80">
                      <span className="block truncate font-medium" title={rule.pattern}>
                        {rule.pattern}
                      </span>
                      {rule.reason && (
                        <span className="block truncate text-xs text-text-muted" title={rule.reason}>
                          {rule.reason}
                        </span>
                      )}
                    </Td>
                    <Td className="whitespace-nowrap text-text-secondary">{MATCH_LABELS[rule.match_type]}</Td>
                    <Td className="whitespace-nowrap text-text-secondary">{scopeLabel(rule, clientNames)}</Td>
                    <Td className="whitespace-nowrap text-text-secondary">
                      {rule.expires_at ? formatDateTime(rule.expires_at) : "Never"}
                    </Td>
                    <Td>
                      <Switch
                        checked={rule.enabled}
                        disabled={readOnly || toggle.isPending}
                        label={`Enable rule for ${rule.pattern}`}
                        onCheckedChange={() => toggle.mutate(rule)}
                      />
                    </Td>
                    <Td className="whitespace-nowrap text-right">
                      <Button
                        variant="ghost"
                        size="icon"
                        disabled={readOnly}
                        aria-label={`Edit rule for ${rule.pattern}`}
                        onClick={() => setEditing(rule)}
                      >
                        <Pencil aria-hidden className="size-4" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon"
                        disabled={readOnly}
                        aria-label={`Delete rule for ${rule.pattern}`}
                        onClick={() => setDeleting(rule)}
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
      <RuleDialog
        open={adding || editing !== undefined}
        rule={editing}
        onClose={() => {
          setAdding(false);
          setEditing(undefined);
        }}
      />
      <ConfirmDialog
        open={deleting !== undefined}
        onOpenChange={(open) => {
          if (!open) setDeleting(undefined);
        }}
        title="Delete this rule?"
        description={`The rule for ${deleting?.pattern ?? ""} stops applying right away.`}
        confirmLabel="Delete rule"
        pending={remove.isPending}
        onConfirm={() => {
          if (deleting) remove.mutate(deleting, { onSettled: () => setDeleting(undefined) });
        }}
      />
    </>
  );
}
