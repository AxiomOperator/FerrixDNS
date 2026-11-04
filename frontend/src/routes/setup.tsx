import { createFileRoute, redirect } from "@tanstack/react-router";

import { SetupPage } from "@/features/auth";
import { queries } from "@/lib/api/hooks";

export const Route = createFileRoute("/setup")({
  beforeLoad: async ({ context }) => {
    const status = await context.queryClient.fetchQuery(queries.authStatus());
    if (!status.setup_required) throw redirect({ to: "/login" });
  },
  component: SetupPage,
});
