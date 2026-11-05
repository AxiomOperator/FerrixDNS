import { createFileRoute } from "@tanstack/react-router";

import { FleetOverviewPage } from "@/features/fleet-overview";
import { OverviewPage } from "@/features/overview";

function Page() {
  const { role } = Route.useRouteContext();
  return role === "controller" ? <FleetOverviewPage /> : <OverviewPage />;
}

export const Route = createFileRoute("/_authenticated/")({
  component: Page,
});
