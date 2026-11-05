import { createFileRoute } from "@tanstack/react-router";

import { SitePolicySettingsPage } from "@/features/settings";

export const Route = createFileRoute("/_authenticated/fleet/policy-settings")({
  component: SitePolicySettingsPage,
});
