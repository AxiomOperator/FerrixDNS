import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, type ReactNode, useEffect, useRef, useState } from "react";
import { toast } from "sonner";

import { ErrorState, Loading } from "@/components/states";
import { Button } from "@/components/ui/button";
import { Card, CardHeader } from "@/components/ui/card";
import { ConfirmDialog, Dialog } from "@/components/ui/dialog";
import { Field, Input, Select } from "@/components/ui/form";
import { Switch } from "@/components/ui/switch";
import { errorMessage } from "@/lib/api/client";
import { type NodeSettings, type NodeSettingsView, api, queries } from "@/lib/api/hooks";
import { splitList } from "@/lib/format";

const RESTART_POLL_MS = 500;
const RESTART_SLOW_MS = 30_000;

/** Where the dashboard will be with these settings, keeping the name in use if it still works. */
export function dashboardUrl(settings: NodeSettings, current: Location = window.location): string {
  const scheme = settings.web_tls_mode === "off" ? "http:" : "https:";
  const split = /^(.*):(\d+)$/.exec(settings.web_listen);
  const address = split?.[1] ?? settings.web_listen;
  const port = split?.[2] ?? current.port;
  const hostname = current.hostname;
  const isLoopback = (name: string) => ["localhost", "127.0.0.1", "[::1]"].includes(name);
  const keepsName =
    address === "0.0.0.0" ||
    address === "[::]" ||
    settings.web_hosts.includes(hostname) ||
    (isLoopback(hostname) && isLoopback(address));
  return `${scheme}//${keepsName ? hostname : address}:${port}`;
}

/** Follows a restart, and says where to go if the dashboard is moving. */
function RestartDialog({
  target,
  bootId,
  onDone,
}: {
  target: string;
  bootId: string;
  onDone: () => void;
}) {
  const moving = target !== window.location.origin;
  const client = useQueryClient();
  const [slow, setSlow] = useState(false);
  const done = useRef(onDone);
  done.current = onDone;

  useEffect(() => {
    if (moving) return undefined;
    let active = true;
    const started = Date.now();
    async function poll() {
      while (active) {
        await new Promise((resolve) => setTimeout(resolve, RESTART_POLL_MS));
        if (Date.now() - started > RESTART_SLOW_MS) setSlow(true);
        const view = await api.nodeSettings().catch(() => undefined);
        if (active && view && view.boot_id !== bootId) {
          await client.invalidateQueries();
          if (view.last_failure) toast.error("The change was undone");
          else if (!view.pending) toast.success("Settings saved and active");
          done.current();
          return;
        }
      }
    }
    void poll();
    return () => {
      active = false;
    };
  }, [moving, bootId, client]);

  if (moving) {
    return (
      <Dialog
        open
        onOpenChange={() => undefined}
        title="The dashboard is moving"
        description="Open the new address and sign in. Unless you keep the change there within 2 minutes, the previous settings come back."
      >
        <a className="font-medium text-accent underline" href={target}>
          {target}
        </a>
      </Dialog>
    );
  }
  return (
    <Dialog
      open
      onOpenChange={() => undefined}
      title="Restarting the node"
      description="DNS stops answering until it's back, usually within a few seconds."
    >
      <p role="status" className="text-sm text-text-secondary">
        {slow ? "This is taking longer than usual. Check the node's log if it doesn't return." : "Waiting for the node…"}
      </p>
    </Dialog>
  );
}

/** Asks whether to keep a change to how the dashboard is reached, before it undoes itself. */
export function NodeChangeBanner() {
  const view = useQuery(queries.nodeSettings());
  const client = useQueryClient();
  const [restart, setRestart] = useState<{ target: string; bootId: string }>();
  const keep = useMutation({
    mutationFn: api.keepNodeSettings,
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ["node-settings"] });
      toast.success("Change kept");
    },
    onError: (error) => toast.error(errorMessage(error)),
  });
  const undo = useMutation({
    mutationFn: api.undoNodeSettings,
    onSuccess: (data) => setRestart({ target: dashboardUrl(data.settings), bootId: data.boot_id }),
    onError: (error) => toast.error(errorMessage(error)),
  });
  const pending = view.data?.pending;

  return (
    <>
      {pending && (
        <div
          role="alert"
          className="flex flex-wrap items-center gap-2 border-b border-border bg-accent-soft px-4 py-2 text-sm"
        >
          <span className="min-w-0 flex-1">
            Keep the change to dashboard access? It undoes itself in {pending.seconds_left} seconds.
          </span>
          <Button size="sm" variant="primary" disabled={keep.isPending} onClick={() => keep.mutate()}>
            Keep change
          </Button>
          <Button size="sm" disabled={undo.isPending} onClick={() => undo.mutate()}>
            Undo
          </Button>
        </div>
      )}
      {restart && <RestartDialog {...restart} onDone={() => setRestart(undefined)} />}
    </>
  );
}

function Toggle({
  label,
  hint,
  checked,
  onChange,
}: {
  label: string;
  hint: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
}) {
  return (
    <div className="flex items-start gap-3">
      <div className="pt-0.5">
        <Switch label={label} checked={checked} onCheckedChange={onChange} />
      </div>
      <div className="min-w-0">
        <p className="text-sm font-medium">{label}</p>
        <p className="text-xs text-text-muted">{hint}</p>
      </div>
    </div>
  );
}

function Section({
  title,
  description,
  children,
}: {
  title: string;
  description: string;
  children: ReactNode;
}) {
  return (
    <Card>
      <CardHeader title={title} description={description} />
      <div className="grid gap-4 px-4 pb-4 sm:grid-cols-2">{children}</div>
    </Card>
  );
}

function Wide({ children }: { children: ReactNode }) {
  return <div className="sm:col-span-2">{children}</div>;
}

const LIST_FIELDS = ["listen", "allow", "upstreams", "web_hosts", "ntp_listen"] as const;
type ListField = (typeof LIST_FIELDS)[number];
type Lists = Record<ListField, string>;

/** Which settings each tab holds, so a tab can show that it has unsaved changes. */
const TAB_FIELDS = {
  dns: [
    "listen",
    "allow",
    "upstreams",
    "upstream_load_balance",
    "dnssec_validate",
    "attempt_timeout_ms",
    "query_timeout_ms",
    "max_concurrent_requests",
    "cache_mib",
    "cache_max_ttl",
    "cache_negative_ttl",
  ],
  dashboard: ["web_listen", "web_hosts", "web_tls_mode", "web_tls_cert", "web_tls_key", "web_insecure_remote"],
  system: ["ntp_listen", "policy_file", "state_dir", "log_filter", "allow_private_list_urls"],
} as const satisfies Record<string, ReadonlyArray<keyof NodeSettings>>;

export type NodeSettingsTab = keyof typeof TAB_FIELDS;

function listsOf(settings: NodeSettings): Lists {
  return {
    listen: settings.listen.join(", "),
    allow: settings.allow.join(", "),
    upstreams: settings.upstreams.join(", "),
    web_hosts: settings.web_hosts.join(", "),
    ntp_listen: settings.ntp_listen.join(", "),
  };
}

/** Edits to the node's settings. They live above the tabs, so changing tabs doesn't lose them. */
export function useNodeSettingsForm() {
  const view = useQuery(queries.nodeSettings());
  const savedText = view.data ? JSON.stringify(view.data.settings) : undefined;
  const [values, setValues] = useState<NodeSettings>();
  const [lists, setLists] = useState<Lists>();
  const [restart, setRestart] = useState<{ target: string; bootId: string }>();

  useEffect(() => {
    if (!savedText) return;
    const saved = JSON.parse(savedText) as NodeSettings;
    setValues(saved);
    setLists(listsOf(saved));
  }, [savedText]);

  const save = useMutation({
    mutationFn: api.saveNodeSettings,
    onSuccess: (result) => {
      if (result.restarting) {
        setRestart({ target: dashboardUrl(result.view.settings), bootId: result.view.boot_id });
      } else {
        toast.success("Nothing changed");
      }
    },
  });

  const current: NodeSettings | undefined =
    values && lists
      ? {
          ...values,
          listen: splitList(lists.listen),
          allow: splitList(lists.allow),
          upstreams: splitList(lists.upstreams),
          web_hosts: splitList(lists.web_hosts),
          ntp_listen: splitList(lists.ntp_listen),
        }
      : undefined;
  const saved = savedText ? (JSON.parse(savedText) as NodeSettings) : undefined;

  function tabIsDirty(tab: NodeSettingsTab) {
    if (!current || !saved) return false;
    return TAB_FIELDS[tab].some((field) => JSON.stringify(current[field]) !== JSON.stringify(saved[field]));
  }

  return {
    view,
    values,
    lists,
    setValues,
    setLists,
    current,
    save,
    restart,
    setRestart,
    tabIsDirty,
    isDirty: current !== undefined && JSON.stringify(current) !== savedText,
    load(settings: NodeSettings) {
      setValues(settings);
      setLists(listsOf(settings));
    },
  };
}

export type NodeSettingsForm = ReturnType<typeof useNodeSettingsForm>;

function SaveBar({ form, view }: { form: NodeSettingsForm; view: NodeSettingsView }) {
  const { save, isDirty, current } = form;
  return (
    <div className="sticky bottom-0 -mx-1 rounded-lg border border-border bg-surface p-3 shadow-sm">
      {save.isError && (
        <p role="alert" className="mb-2 text-sm font-medium text-danger">
          {errorMessage(save.error)}
        </p>
      )}
      <div className="flex flex-wrap items-center justify-end gap-2">
        <p className="min-w-0 flex-1 text-sm text-text-secondary">
          {view.pending
            ? "Keep or undo the last change before making another."
            : "You have unsaved changes. Saving restarts the node, and DNS stops for a few seconds."}
        </p>
        <Button
          type="button"
          disabled={save.isPending}
          onClick={() => {
            save.reset();
            form.load(view.settings);
          }}
        >
          Discard
        </Button>
        <Button type="submit" variant="primary" disabled={save.isPending || Boolean(view.pending) || !isDirty || !current}>
          Save and restart
        </Button>
      </div>
    </div>
  );
}

/** One tab of the node's settings, with what they share: errors, saving and restarting. */
export function NodeSettingsPanel({ form, children }: { form: NodeSettingsForm; children: ReactNode }) {
  const [confirming, setConfirming] = useState(false);
  const { view, current, save, restart } = form;
  if (view.isPending) return <Loading />;
  if (view.isError) return <ErrorState error={view.error} onRetry={() => void view.refetch()} />;

  return (
    <form
      className="space-y-4"
      onSubmit={(event: FormEvent) => {
        event.preventDefault();
        setConfirming(true);
      }}
    >
      {view.data.last_failure && (
        <p role="alert" className="text-sm font-medium text-danger">
          The last change was undone. {view.data.last_failure}
        </p>
      )}
      {children}
      {form.isDirty && <SaveBar form={form} view={view.data} />}
      <ConfirmDialog
        open={confirming}
        onOpenChange={setConfirming}
        title="Restart the node?"
        description="DNS stops answering until the node is back, usually within a few seconds. A blocking pause ends, and the cache starts empty."
        confirmLabel="Save and restart"
        pending={save.isPending}
        onConfirm={() => {
          if (current) save.mutate(current, { onSettled: () => setConfirming(false) });
        }}
      />
      {restart && <RestartDialog {...restart} onDone={() => form.setRestart(undefined)} />}
    </form>
  );
}

function controls(form: NodeSettingsForm) {
  const { values, lists, setValues, setLists } = form;
  if (!values || !lists) return undefined;
  return {
    values,
    set: (change: Partial<NodeSettings>) => setValues({ ...values, ...change }),
    number: (id: string, field: keyof NodeSettings, min: number) => (
      <Input
        id={id}
        type="number"
        min={min}
        required
        value={values[field] as number}
        onChange={(event) => setValues({ ...values, [field]: Number(event.target.value) })}
      />
    ),
    list: (id: string, field: ListField, required = false) => (
      <Input
        id={id}
        autoComplete="off"
        required={required}
        value={lists[field]}
        onChange={(event) => setLists({ ...lists, [field]: event.target.value })}
      />
    ),
  };
}

export function DnsSettings({ form }: { form: NodeSettingsForm }) {
  const ui = controls(form);
  if (!ui) return null;
  const { values, set, number, list } = ui;
  return (
    <>
      <Section title="Upstream servers" description="Where this node sends queries it can't answer itself.">
        <Wide>
          <Field
            label="Servers"
            htmlFor="node-upstreams"
            hint="Separated by commas: 1.1.1.1, tls://cloudflare-dns.com@1.1.1.1 or https://cloudflare-dns.com/dns-query@1.1.1.1"
          >
            {list("node-upstreams", "upstreams", true)}
          </Field>
        </Wide>
        <Wide>
          <Toggle
            label="Load balance"
            hint="Shares queries between the servers. When off, they're tried in order, and the later ones are only used if the earlier ones fail."
            checked={values.upstream_load_balance}
            onChange={(upstream_load_balance) => set({ upstream_load_balance })}
          />
        </Wide>
        <Wide>
          <Toggle
            label="DNSSEC validation"
            hint="Checks that answers are genuine. Upstreams must return signatures, or names stop resolving."
            checked={values.dnssec_validate}
            onChange={(dnssec_validate) => set({ dnssec_validate })}
          />
        </Wide>
        <Wide>
          <details>
            <summary className="cursor-pointer text-sm font-medium">Time limits and capacity</summary>
            <div className="mt-3 grid gap-4 sm:grid-cols-3">
              <Field label="Time for one server (ms)" htmlFor="node-attempt">
                {number("node-attempt", "attempt_timeout_ms", 1)}
              </Field>
              <Field label="Time for a whole query (ms)" htmlFor="node-query">
                {number("node-query", "query_timeout_ms", 1)}
              </Field>
              <Field label="Requests in flight" htmlFor="node-concurrent" hint="Beyond this, queries get an error.">
                {number("node-concurrent", "max_concurrent_requests", 1)}
              </Field>
            </div>
          </details>
        </Wide>
      </Section>
      <Section title="Listening" description="Where this node answers DNS, and who it answers.">
        <Field label="DNS addresses" htmlFor="node-listen" hint="Separated by commas, like 192.168.1.10:53.">
          {list("node-listen", "listen", true)}
        </Field>
        <Field
          label="Networks allowed to query"
          htmlFor="node-allow"
          hint="Separated by commas. Everyone else is refused."
        >
          {list("node-allow", "allow", true)}
        </Field>
      </Section>
      <Card>
        <CardHeader title="Cache" description="Recent answers, kept in memory." />
        <div className="grid gap-4 px-4 pb-4 sm:grid-cols-3">
          <Field label="Memory (MiB)" htmlFor="node-cache" hint="0 turns the cache off.">
            {number("node-cache", "cache_mib", 0)}
          </Field>
          <Field label="Longest time to keep an answer (seconds)" htmlFor="node-cache-ttl">
            {number("node-cache-ttl", "cache_max_ttl", 1)}
          </Field>
          <Field label='Longest time to keep "not found" (seconds)' htmlFor="node-cache-negative">
            {number("node-cache-negative", "cache_negative_ttl", 0)}
          </Field>
        </div>
      </Card>
    </>
  );
}

export function DashboardSettings({ form }: { form: NodeSettingsForm }) {
  const ui = controls(form);
  if (!ui) return null;
  const { values, set, list } = ui;
  return (
    <Section
      title="Dashboard access"
      description="How this dashboard is reached. A change here undoes itself after 2 minutes unless you keep it."
    >
      <Field label="Address" htmlFor="node-web-listen" hint="Like 192.168.1.10:8443, or 0.0.0.0:8443 for every address.">
        <Input
          id="node-web-listen"
          autoComplete="off"
          required
          value={values.web_listen}
          onChange={(event) => set({ web_listen: event.target.value })}
        />
      </Field>
      <Field
        label="Names it answers to"
        htmlFor="node-web-hosts"
        hint="Separated by commas, like dns.home.arpa. Loopback always works."
      >
        {list("node-web-hosts", "web_hosts")}
      </Field>
      <Field label="TLS" htmlFor="node-web-tls">
        <Select
          id="node-web-tls"
          value={values.web_tls_mode}
          onChange={(event) => set({ web_tls_mode: event.target.value as NodeSettings["web_tls_mode"] })}
        >
          <option value="off">Off (plain HTTP)</option>
          <option value="self_signed">Self-signed certificate</option>
          <option value="files">My certificate files</option>
        </Select>
      </Field>
      {values.web_tls_mode === "off" && (
        <Toggle
          label="Allow plain HTTP on a network address"
          hint="Anyone on the network path can read passwords and query logs."
          checked={values.web_insecure_remote}
          onChange={(web_insecure_remote) => set({ web_insecure_remote })}
        />
      )}
      {values.web_tls_mode === "files" && (
        <>
          <Field label="Certificate file on this node" htmlFor="node-web-cert" hint="PEM format.">
            <Input
              id="node-web-cert"
              autoComplete="off"
              required
              value={values.web_tls_cert ?? ""}
              onChange={(event) => set({ web_tls_cert: event.target.value })}
            />
          </Field>
          <Field label="Private key file on this node" htmlFor="node-web-key" hint="PEM format.">
            <Input
              id="node-web-key"
              autoComplete="off"
              required
              value={values.web_tls_key ?? ""}
              onChange={(event) => set({ web_tls_key: event.target.value })}
            />
          </Field>
        </>
      )}
    </Section>
  );
}

export function SystemSettings({ form }: { form: NodeSettingsForm }) {
  const ui = controls(form);
  const view = form.view.data;
  if (!ui || !view) return null;
  const { values, set, list } = ui;
  return (
    <>
      <Section title="Time server" description="Shares this machine's clock with devices on your network.">
        <Wide>
          <Field
            label="NTP addresses"
            htmlFor="node-ntp"
            hint="Separated by commas, like 192.168.1.10:123. Leave empty to turn it off."
          >
            {list("node-ntp", "ntp_listen")}
          </Field>
        </Wide>
      </Section>
      <Section title="Files and logs" description="What this node stores, reads and logs.">
        <Field
          label="Data folder"
          htmlFor="node-state-dir"
          hint="Saving copies your data to an empty folder. The old folder stays as it was."
        >
          <Input
            id="node-state-dir"
            autoComplete="off"
            required
            value={values.state_dir}
            onChange={(event) => set({ state_dir: event.target.value })}
          />
        </Field>
        <Field
          label="Log filter"
          htmlFor="node-log-filter"
          hint="Like info or warn,ferrixdns=debug. More detail can log the names people look up."
        >
          <Input
            id="node-log-filter"
            autoComplete="off"
            required
            value={values.log_filter}
            onChange={(event) => set({ log_filter: event.target.value })}
          />
        </Field>
        <Field
          label="Policy file on this node"
          htmlFor="node-policy"
          hint="Optional. With a file, rules and sources become read-only here."
        >
          <Input
            id="node-policy"
            autoComplete="off"
            value={values.policy_file ?? ""}
            onChange={(event) => set({ policy_file: event.target.value || null })}
          />
        </Field>
        <Toggle
          label="Allow list downloads from private addresses"
          hint="Lets a source on your own network work, but a source URL can then reach services on it."
          checked={values.allow_private_list_urls}
          onChange={(allow_private_list_urls) => set({ allow_private_list_urls })}
        />
      </Section>
      {view.changed.length > 0 && (
        <Card>
          <CardHeader
            title="Startup values"
            description={`${view.changed.length} ${view.changed.length === 1 ? "setting differs" : "settings differ"} from how this node was started. This fills in the startup values on every tab, for you to review and save.`}
            actions={
              <Button type="button" onClick={() => form.load(view.startup)}>
                Use startup values
              </Button>
            }
          />
        </Card>
      )}
    </>
  );
}
