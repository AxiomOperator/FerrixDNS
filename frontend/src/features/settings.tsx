import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { Tabs } from "radix-ui";
import { type FormEvent, useEffect, useRef, useState } from "react";
import { toast } from "sonner";

import { ErrorState, Loading, PageHeader, ReadOnlyNotice } from "@/components/states";
import { Button } from "@/components/ui/button";
import { Card, CardHeader } from "@/components/ui/card";
import { Field, Input, Select } from "@/components/ui/form";
import {
  DashboardSettings,
  DnsSettings,
  NodeSettingsPanel,
  SystemSettings,
  useNodeSettingsForm,
} from "@/features/node-settings";
import { splitList } from "@/lib/format";
import { errorMessage, setCsrfToken } from "@/lib/api/client";
import { type Settings, api, queries, usePolicyMutation } from "@/lib/api/hooks";
import { type Theme, setTheme, storedTheme } from "@/lib/theme";

const GIB = 1024 ** 3;

const MODE_HINTS: Record<Settings["query_log_mode"], string> = {
  full: "Keeps each query and which device asked, on this node only. Needed to investigate blocks per device.",
  anonymized: "Keeps each query, but not which device asked.",
  aggregate_only: "Keeps counts only. The Query Explorer stays empty.",
  disabled: "Records nothing. Overview stays empty.",
};

function SettingsForm({ settings, readOnly }: { settings: Settings; readOnly: boolean }) {
  const [values, setValues] = useState(settings);
  const [exempt, setExempt] = useState(settings.rate_limit_exempt.join(", "));
  // This page updates live, so show changes made elsewhere, unless they'd replace unsaved edits here.
  const shown = useRef(settings);
  useEffect(() => {
    const previous = shown.current;
    shown.current = settings;
    const untouched =
      JSON.stringify(values) === JSON.stringify(previous) &&
      exempt === previous.rate_limit_exempt.join(", ");
    if (untouched) {
      setValues(settings);
      setExempt(settings.rate_limit_exempt.join(", "));
    }
    // Only new settings from the node should run this, not typing.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [settings]);
  const save = usePolicyMutation(
    () => api.saveSettings({ ...values, rate_limit_exempt: splitList(exempt) }),
    "Settings saved and active",
  );

  function submit(event: FormEvent) {
    event.preventDefault();
    save.mutate(undefined, {
      onSuccess: (saved) => {
        shown.current = saved;
        setValues(saved);
        setExempt(saved.rate_limit_exempt.join(", "));
      },
    });
  }

  return (
    <form onSubmit={submit} className="space-y-4">
      <Card>
        <CardHeader title="Blocking" description="How this node answers blocked queries." />
        <div className="grid gap-4 px-4 pb-4 sm:grid-cols-2">
          <Field
            label="Response"
            htmlFor="block-response"
            hint="Domain not found is the safest choice for most networks."
          >
            <Select
              id="block-response"
              disabled={readOnly}
              value={values.block_response}
              onChange={(event) =>
                setValues({ ...values, block_response: event.target.value as Settings["block_response"] })
              }
            >
              <option value="nxdomain">Domain not found (NXDOMAIN)</option>
              <option value="zero_address">Zero address (0.0.0.0 and ::)</option>
            </Select>
          </Field>
          <Field
            label="Client cache time (seconds)"
            htmlFor="block-ttl"
            hint="Devices may keep a block this long after you allow a domain."
          >
            <Input
              id="block-ttl"
              type="number"
              min={0}
              max={86400}
              required
              disabled={readOnly}
              value={values.block_ttl_seconds}
              onChange={(event) => setValues({ ...values, block_ttl_seconds: Number(event.target.value) })}
            />
          </Field>
        </div>
      </Card>
      <Card>
        <CardHeader
          title="Query limit"
          description="Refuses queries from a device that sends too many, so one misbehaving device can't overload this node."
        />
        <div className="grid gap-4 px-4 pb-4 sm:grid-cols-2">
          <Field
            label="Queries per minute, for each address"
            htmlFor="rate-limit"
            hint="This is also the largest burst. 0 turns the limit off."
          >
            <Input
              id="rate-limit"
              type="number"
              min={0}
              required
              disabled={readOnly}
              value={values.rate_limit_queries_per_minute}
              onChange={(event) =>
                setValues({ ...values, rate_limit_queries_per_minute: Number(event.target.value) })
              }
            />
          </Field>
          <Field
            label="Addresses with no limit"
            htmlFor="rate-exempt"
            hint="Separated by commas. Add a router here if it forwards a whole network's queries."
          >
            <Input
              id="rate-exempt"
              autoComplete="off"
              disabled={readOnly}
              value={exempt}
              onChange={(event) => setExempt(event.target.value)}
            />
          </Field>
        </div>
      </Card>
      <Card>
        <CardHeader title="Query logging" description="What this node records. It stays on this node." />
        <div className="grid gap-4 px-4 pb-4 sm:grid-cols-3">
          <Field label="Mode" htmlFor="log-mode" hint={MODE_HINTS[values.query_log_mode]}>
            <Select
              id="log-mode"
              disabled={readOnly}
              value={values.query_log_mode}
              onChange={(event) =>
                setValues({ ...values, query_log_mode: event.target.value as Settings["query_log_mode"] })
              }
            >
              <option value="full">Full history</option>
              <option value="anonymized">Anonymized</option>
              <option value="aggregate_only">Counts only</option>
              <option value="disabled">Off</option>
            </Select>
          </Field>
          <Field label="Keep history for (days)" htmlFor="log-days">
            <Input
              id="log-days"
              type="number"
              min={1}
              required
              disabled={readOnly}
              value={values.query_history_days}
              onChange={(event) => setValues({ ...values, query_history_days: Number(event.target.value) })}
            />
          </Field>
          <Field
            label="Maximum history size (GiB)"
            htmlFor="log-size"
            hint="Whichever limit is reached first applies."
          >
            <Input
              id="log-size"
              type="number"
              min={0.1}
              step={0.1}
              required
              disabled={readOnly}
              value={Math.round((values.query_history_max_bytes / GIB) * 10) / 10}
              onChange={(event) =>
                setValues({
                  ...values,
                  query_history_max_bytes: Math.round(Number(event.target.value) * GIB),
                })
              }
            />
          </Field>
        </div>
      </Card>
      <div className="flex flex-wrap items-center justify-end gap-3">
        <p className="min-w-0 flex-1 text-sm text-text-secondary">These apply right away, without a restart.</p>
        <Button type="submit" variant="primary" disabled={readOnly || save.isPending}>
          Save settings
        </Button>
      </div>
    </form>
  );
}

function PasswordCard() {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [error, setError] = useState<string>();
  const [pending, setPending] = useState(false);
  const client = useQueryClient();
  const navigate = useNavigate();

  async function submit(event: FormEvent) {
    event.preventDefault();
    setPending(true);
    setError(undefined);
    try {
      await api.changePassword({ current_password: current, new_password: next });
      setCsrfToken(undefined);
      client.clear();
      toast.success("Password changed. Please sign in again.");
      await navigate({ to: "/login" });
    } catch (failure) {
      setError(errorMessage(failure));
      setPending(false);
    }
  }

  return (
    <Card>
      <CardHeader title="Password" description="Changing it signs out every session." />
      <form
        className="grid gap-4 px-4 pb-4 sm:grid-cols-[1fr_1fr_auto] sm:items-start"
        onSubmit={(event) => void submit(event)}
      >
        <Field label="Current password" htmlFor="current-password" error={error}>
          <Input
            id="current-password"
            type="password"
            autoComplete="current-password"
            required
            value={current}
            onChange={(event) => setCurrent(event.target.value)}
          />
        </Field>
        <Field label="New password" htmlFor="new-password" hint="At least 10 characters.">
          <Input
            id="new-password"
            type="password"
            autoComplete="new-password"
            required
            minLength={10}
            value={next}
            onChange={(event) => setNext(event.target.value)}
          />
        </Field>
        <Button type="submit" className="sm:mt-6" disabled={pending}>
          Change password
        </Button>
      </form>
    </Card>
  );
}

function AppearanceCard() {
  const [theme, setCurrent] = useState<Theme>(storedTheme);
  return (
    <Card>
      <CardHeader title="Appearance" description="Saved in this browser." />
      <div className="max-w-xs px-4 pb-4">
        <Field label="Theme" htmlFor="theme">
          <Select
            id="theme"
            value={theme}
            onChange={(event) => {
              const next = event.target.value as Theme;
              setCurrent(next);
              setTheme(next);
            }}
          >
            <option value="system">Match system</option>
            <option value="light">Light</option>
            <option value="dark">Dark</option>
          </Select>
        </Field>
      </div>
    </Card>
  );
}

export const SETTINGS_TABS = ["blocking", "dns", "dashboard", "system", "account"] as const;
export type SettingsTab = (typeof SETTINGS_TABS)[number];

const TAB_LABELS: Record<SettingsTab, string> = {
  blocking: "Blocking and logs",
  dns: "DNS",
  dashboard: "Dashboard",
  system: "System",
  account: "Account",
};

export function SettingsPage({
  readOnly,
  tab,
  onTabChange,
}: {
  readOnly: boolean;
  tab: SettingsTab;
  onTabChange: (tab: SettingsTab) => void;
}) {
  const settings = useQuery(queries.settings());
  const node = useNodeSettingsForm();

  return (
    <>
      <PageHeader title="Settings" />
      <Tabs.Root value={tab} onValueChange={(value) => onTabChange(value as SettingsTab)}>
        <Tabs.List
          aria-label="Settings sections"
          className="mb-4 flex gap-1 overflow-x-auto border-b border-border"
        >
          {SETTINGS_TABS.map((name) => (
            <Tabs.Trigger
              key={name}
              value={name}
              className="-mb-px cursor-pointer border-b-2 border-transparent px-3 py-2 text-sm whitespace-nowrap text-text-secondary hover:text-text data-[state=active]:border-accent data-[state=active]:font-medium data-[state=active]:text-text"
            >
              {TAB_LABELS[name]}
              {name !== "blocking" && name !== "account" && node.tabIsDirty(name) && (
                <span className="ml-1.5 text-accent">
                  <span aria-hidden>•</span>
                  <span className="sr-only">(unsaved changes)</span>
                </span>
              )}
            </Tabs.Trigger>
          ))}
        </Tabs.List>
        <Tabs.Content value="blocking">
          {readOnly && <ReadOnlyNotice />}
          {settings.isPending && <Loading />}
          {settings.isError && <ErrorState error={settings.error} onRetry={() => void settings.refetch()} />}
          {settings.data && <SettingsForm settings={settings.data} readOnly={readOnly} />}
        </Tabs.Content>
        <Tabs.Content value="dns">
          <NodeSettingsPanel form={node}>
            <DnsSettings form={node} />
          </NodeSettingsPanel>
        </Tabs.Content>
        <Tabs.Content value="dashboard">
          <NodeSettingsPanel form={node}>
            <DashboardSettings form={node} />
          </NodeSettingsPanel>
        </Tabs.Content>
        <Tabs.Content value="system">
          <NodeSettingsPanel form={node}>
            <SystemSettings form={node} />
          </NodeSettingsPanel>
        </Tabs.Content>
        <Tabs.Content value="account" className="space-y-4">
          <PasswordCard />
          <AppearanceCard />
        </Tabs.Content>
      </Tabs.Root>
    </>
  );
}
