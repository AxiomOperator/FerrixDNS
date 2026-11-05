import { useMutation } from "@tanstack/react-query";
import { Link, useNavigate, useSearch } from "@tanstack/react-router";
import { CircleAlert, CircleCheck, CircleSlash, Info } from "lucide-react";
import { type FormEvent, useEffect, useRef, useState } from "react";

import { PageHeader } from "@/components/states";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardHeader } from "@/components/ui/card";
import { Field, Input, Select } from "@/components/ui/form";
import { Table, TableWrap, Td, Th } from "@/components/ui/table";
import { type Schemas, errorMessage } from "@/lib/api/client";
import { api } from "@/lib/api/hooks";
import { formatDateTime, shortRevision } from "@/lib/format";

const RECORD_TYPES = ["A", "AAAA", "CNAME", "HTTPS", "MX", "NS", "PTR", "SOA", "SRV", "TXT"];

const STEP_LOOK = {
  ok: { icon: CircleCheck, className: "text-success", label: "Fine" },
  info: { icon: Info, className: "text-text-muted", label: "Note" },
  warning: { icon: CircleAlert, className: "text-warning", label: "Warning" },
  stopped: { icon: CircleSlash, className: "text-danger", label: "This decides the answer" },
} as const;

function ResultBadge({ result }: { result: string }) {
  switch (result) {
    case "blocked":
      return <Badge tone="danger">Blocked</Badge>;
    case "refused":
      return <Badge tone="danger">Refused</Badge>;
    case "failed":
      return <Badge tone="error">Fails</Badge>;
    case "stale":
      return <Badge tone="warning">Expired answer</Badge>;
    case "cached":
      return <Badge tone="success">Cached</Badge>;
    case "local":
      return <Badge tone="success">Local</Badge>;
    default:
      return <Badge tone="success">Answered</Badge>;
  }
}

function Steps({ steps }: { steps: Schemas["DiagnosticStep"][] }) {
  return (
    <ol className="divide-y divide-border border-t border-border">
      {steps.map((step, index) => {
        const look = STEP_LOOK[step.status];
        const Icon = look.icon;
        return (
          <li key={`${step.title}-${index}`} className="flex items-start gap-3 px-4 py-3">
            <Icon aria-label={look.label} className={`mt-0.5 size-4 shrink-0 ${look.className}`} />
            <div className="min-w-0">
              <p className="text-sm font-medium">{step.title}</p>
              <p className="text-sm text-text-secondary">{step.detail}</p>
            </div>
          </li>
        );
      })}
    </ol>
  );
}

function Upstreams({ probes }: { probes: Schemas["DiagnosticProbe"][] }) {
  return (
    <Card>
      <CardHeader title="What each server said" description="Each server was asked directly, just now." />
      <TableWrap>
        <Table>
          <thead>
            <tr>
              <Th>Server</Th>
              <Th>Result</Th>
              <Th className="text-right">Time</Th>
              <Th>Answer</Th>
            </tr>
          </thead>
          <tbody>
            {probes.map((probe) => (
              <tr key={probe.server}>
                <Td className="font-medium">{probe.server}</Td>
                <Td>
                  <Badge tone={probe.ok ? "success" : "error"}>
                    {probe.rcode ?? "No response"}
                  </Badge>
                </Td>
                <Td className="text-right">{probe.latency_ms.toFixed(1)} ms</Td>
                <Td className="break-all text-text-secondary">
                  {probe.error ?? (probe.answers.length > 0 ? probe.answers.join("; ") : "No records")}
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      </TableWrap>
    </Card>
  );
}

function Recent({ events, name }: { events: Schemas["QueryEventDto"][]; name: string }) {
  return (
    <Card>
      <CardHeader
        title="What devices really got"
        description="Recent queries with this name in them. If there are none, devices may not be asking this node at all."
        actions={
          <Link
            to="/queries"
            search={{ qname: name }}
            className="text-sm font-medium text-accent underline underline-offset-2"
          >
            Open in Query Explorer
          </Link>
        }
      />
      {events.length === 0 ? (
        <p className="px-4 pb-4 text-sm text-text-muted">No recent queries.</p>
      ) : (
        <TableWrap>
          <Table>
            <thead>
              <tr>
                <Th>Time</Th>
                <Th>Name</Th>
                <Th>Type</Th>
                <Th>Result</Th>
                <Th>Client</Th>
              </tr>
            </thead>
            <tbody>
              {events.map((event, index) => (
                <tr key={`${event.occurred_at}-${index}`}>
                  <Td>{formatDateTime(event.occurred_at)}</Td>
                  <Td className="break-all">{event.question.name}</Td>
                  <Td>{event.question.type}</Td>
                  <Td>{event.decision.action.replace("_", " ")}</Td>
                  <Td>{event.client.id ?? event.client.address ?? "Not recorded"}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
        </TableWrap>
      )}
    </Card>
  );
}

export function DiagnosticsPage() {
  const search = useSearch({ from: "/_authenticated/diagnostics" });
  const navigate = useNavigate({ from: "/diagnostics" });
  const [name, setName] = useState(search.name ?? "");
  const [type, setType] = useState(search.type ?? "A");
  const [client, setClient] = useState(search.client ?? "");

  const run = useMutation({ mutationFn: api.diagnose });
  const { mutate } = run;

  // A link from the Query Explorer starts straight away.
  const started = useRef(false);
  useEffect(() => {
    if (!started.current && search.name) {
      started.current = true;
      mutate({ name: search.name, type: search.type ?? "A", client_ip: search.client });
    }
  }, [search, mutate]);

  function submit(event: FormEvent) {
    event.preventDefault();
    void navigate({ search: { name, type, client: client || undefined }, replace: true });
    run.mutate({ name, type, client_ip: client || undefined });
  }
  const report = run.data;

  return (
    <>
      <PageHeader
        title="Diagnostics"
        description="See how this node would answer a query right now, and why. Upstream servers are asked directly, and nothing on the node changes."
      />
      <Card className="mb-4 p-4">
        <form className="grid items-start gap-3 sm:grid-cols-[2fr_1fr_1.5fr_auto]" onSubmit={submit}>
          <Field label="Name" htmlFor="diagnose-name">
            <Input
              id="diagnose-name"
              required
              autoComplete="off"
              placeholder="example.com"
              value={name}
              onChange={(event) => setName(event.target.value)}
            />
          </Field>
          <Field label="Type" htmlFor="diagnose-type">
            <Select id="diagnose-type" value={type} onChange={(event) => setType(event.target.value)}>
              {RECORD_TYPES.map((recordType) => (
                <option key={recordType}>{recordType}</option>
              ))}
            </Select>
          </Field>
          <Field label="Device address (optional)" htmlFor="diagnose-client">
            <Input
              id="diagnose-client"
              autoComplete="off"
              placeholder="192.168.1.20"
              value={client}
              onChange={(event) => setClient(event.target.value)}
            />
          </Field>
          <Button type="submit" variant="primary" className="sm:mt-6" disabled={run.isPending}>
            {run.isPending ? "Checking…" : "Check"}
          </Button>
        </form>
        {run.isError && (
          <p role="alert" className="mt-3 text-sm font-medium text-danger">
            {errorMessage(run.error)}
          </p>
        )}
      </Card>
      {report && (
        <div className="space-y-4">
          <Card>
            <div className="p-4">
              <div className="flex flex-wrap items-center gap-2">
                <ResultBadge result={report.result} />
                <span className="text-sm font-medium break-all">
                  {report.name} {report.type}
                </span>
              </div>
              <p role="status" className="mt-2 text-sm">
                {report.summary}
              </p>
              {report.answers.length > 0 && (
                <ul className="mt-2 space-y-0.5 font-mono text-xs break-all text-text-secondary">
                  {report.answers.map((answer) => (
                    <li key={answer}>{answer}</li>
                  ))}
                </ul>
              )}
              <p className="mt-2 text-xs text-text-muted">
                Policy revision {shortRevision(report.revision)}
              </p>
            </div>
            <Steps steps={report.steps} />
          </Card>
          {report.upstreams.length > 0 && <Upstreams probes={report.upstreams} />}
          <Recent events={report.recent} name={report.name} />
        </div>
      )}
    </>
  );
}
