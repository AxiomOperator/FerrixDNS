import { createFileRoute } from "@tanstack/react-router";

import { ActivityPage } from "@/features/fleet";

export const Route = createFileRoute("/_authenticated/fleet/activity")({
  component: ActivityPage,
});
