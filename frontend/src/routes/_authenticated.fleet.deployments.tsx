import { createFileRoute } from "@tanstack/react-router";

import { DeploymentsPage } from "@/features/fleet";

export const Route = createFileRoute("/_authenticated/fleet/deployments")({
  component: DeploymentsPage,
});
