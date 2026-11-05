import { createFileRoute } from "@tanstack/react-router";

import { NodesPage } from "@/features/fleet";

export const Route = createFileRoute("/_authenticated/fleet/nodes")({
  component: NodesPage,
});
