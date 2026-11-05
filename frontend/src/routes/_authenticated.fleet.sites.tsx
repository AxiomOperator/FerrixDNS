import { createFileRoute } from "@tanstack/react-router";

import { SitesPage } from "@/features/fleet";

export const Route = createFileRoute("/_authenticated/fleet/sites")({
  component: SitesPage,
});
