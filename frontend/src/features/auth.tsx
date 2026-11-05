import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { Filter } from "lucide-react";
import { type FormEvent, type ReactNode, useState } from "react";

import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Field, Input } from "@/components/ui/form";
import { errorMessage, setCsrfToken } from "@/lib/api/client";
import { api, queries } from "@/lib/api/hooks";

const MIN_PASSWORD_LENGTH = 10;

function AuthCard({ title, description, children }: { title: string; description: ReactNode; children: ReactNode }) {
  return (
    <main className="flex min-h-dvh items-center justify-center p-4">
      <Card className="w-full max-w-sm p-6">
        <div className="mb-5 flex items-center gap-2">
          <span className="flex size-7 items-center justify-center rounded-md bg-accent text-accent-text">
            <Filter aria-hidden className="size-4" />
          </span>
          <span className="font-semibold">FerrixDNS</span>
        </div>
        <h1 className="text-lg font-semibold">{title}</h1>
        <p className="mt-1 mb-5 text-sm text-text-muted">{description}</p>
        {children}
      </Card>
    </main>
  );
}

function useFinishSignIn() {
  const client = useQueryClient();
  const navigate = useNavigate();
  return async (session: Awaited<ReturnType<typeof api.login>>) => {
    setCsrfToken(session.csrf_token);
    client.setQueryData(queries.session().queryKey, session);
    client.setQueryData(queries.authStatus().queryKey, { setup_required: false, role: session.role });
    await navigate({ to: "/" });
  };
}

export function LoginPage() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string>();
  const [pending, setPending] = useState(false);
  const finish = useFinishSignIn();

  async function submit(event: FormEvent) {
    event.preventDefault();
    setPending(true);
    setError(undefined);
    try {
      await finish(await api.login({ username, password }));
    } catch (failure) {
      setError(errorMessage(failure));
      setPending(false);
    }
  }

  return (
    <AuthCard title="Sign in" description="Manage filtering and see what's happening.">
      <form className="space-y-4" onSubmit={(event) => void submit(event)}>
        <Field label="Username" htmlFor="username">
          <Input
            id="username"
            autoComplete="username"
            required
            value={username}
            onChange={(event) => setUsername(event.target.value)}
          />
        </Field>
        <Field label="Password" htmlFor="password" error={error}>
          <Input
            id="password"
            type="password"
            autoComplete="current-password"
            required
            value={password}
            onChange={(event) => setPassword(event.target.value)}
          />
        </Field>
        <Button type="submit" variant="primary" className="w-full" disabled={pending}>
          {pending ? "Signing in…" : "Sign in"}
        </Button>
      </form>
    </AuthCard>
  );
}

export function SetupPage() {
  const [token, setToken] = useState("");
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [error, setError] = useState<string>();
  const [pending, setPending] = useState(false);
  const finish = useFinishSignIn();
  const status = useQuery(queries.authStatus());

  const tooShort = password.length > 0 && password.length < MIN_PASSWORD_LENGTH;
  const mismatch = confirmation.length > 0 && password !== confirmation;

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (password.length < MIN_PASSWORD_LENGTH || password !== confirmation) return;
    setPending(true);
    setError(undefined);
    try {
      await finish(await api.setup({ token, username, password }));
    } catch (failure) {
      setError(errorMessage(failure));
      setPending(false);
    }
  }

  const isController = status.data?.role === "controller";
  return (
    <AuthCard
      title={isController ? "Set up this controller" : "Set up this node"}
      description={`Create the administrator account. The ${isController ? "controller" : "node"} prints a one-time setup token in its log when it starts.`}
    >
      <form className="space-y-4" onSubmit={(event) => void submit(event)}>
        <Field label="Setup token" htmlFor="token" error={error}>
          <Input
            id="token"
            autoComplete="off"
            required
            className="font-mono"
            value={token}
            onChange={(event) => setToken(event.target.value)}
          />
        </Field>
        <Field label="Username" htmlFor="username">
          <Input
            id="username"
            autoComplete="username"
            required
            value={username}
            onChange={(event) => setUsername(event.target.value)}
          />
        </Field>
        <Field
          label="Password"
          htmlFor="password"
          hint={`At least ${MIN_PASSWORD_LENGTH} characters.`}
          error={tooShort ? `Use at least ${MIN_PASSWORD_LENGTH} characters.` : undefined}
        >
          <Input
            id="password"
            type="password"
            autoComplete="new-password"
            required
            value={password}
            onChange={(event) => setPassword(event.target.value)}
          />
        </Field>
        <Field
          label="Confirm password"
          htmlFor="confirmation"
          error={mismatch ? "The passwords don't match." : undefined}
        >
          <Input
            id="confirmation"
            type="password"
            autoComplete="new-password"
            required
            value={confirmation}
            onChange={(event) => setConfirmation(event.target.value)}
          />
        </Field>
        <p className="rounded-md bg-surface-muted px-3 py-2 text-xs text-text-secondary">
          {isController
            ? "Each node keeps its own query history. Only query counts reach this controller."
            : "By default this node keeps each query, including which device asked, for 7 days. It stays on this node, and you can change it in Settings."}
        </p>
        <Button type="submit" variant="primary" className="w-full" disabled={pending}>
          {pending ? "Setting up…" : "Create administrator"}
        </Button>
      </form>
    </AuthCard>
  );
}
