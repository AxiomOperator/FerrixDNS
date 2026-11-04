import { createFileRoute, redirect, useRouter } from "@tanstack/react-router";
import { useEffect } from "react";

import { AppShell } from "@/components/app-shell";
import { ApiError, setCsrfToken, setUnauthenticatedHandler } from "@/lib/api/client";
import { queries } from "@/lib/api/hooks";

function Authenticated() {
  const router = useRouter();
  const { queryClient } = Route.useRouteContext();
  useEffect(() => {
    // A session can end while the page is open, such as after a password change elsewhere.
    setUnauthenticatedHandler(() => {
      setCsrfToken(undefined);
      queryClient.clear();
      void router.navigate({ to: "/login" });
    });
    return () => setUnauthenticatedHandler(() => undefined);
  }, [queryClient, router]);
  return <AppShell />;
}

export const Route = createFileRoute("/_authenticated")({
  beforeLoad: async ({ context }) => {
    try {
      const session = await context.queryClient.ensureQueryData(queries.session());
      setCsrfToken(session.csrf_token);
      return { policyReadOnly: session.policy_read_only };
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) {
        const status = await context.queryClient.fetchQuery(queries.authStatus());
        throw redirect({ to: status.setup_required ? "/setup" : "/login" });
      }
      throw error;
    }
  },
  component: Authenticated,
  errorComponent: ({ error }) => (
    <main className="flex min-h-dvh items-center justify-center p-4 text-center">
      <p role="alert" className="text-sm font-medium">
        {error instanceof Error ? error.message : "Something went wrong"}
      </p>
    </main>
  ),
});
