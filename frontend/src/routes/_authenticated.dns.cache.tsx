import { createFileRoute } from "@tanstack/react-router";

import { CachePage } from "@/features/cache";

export const Route = createFileRoute("/_authenticated/dns/cache")({
  component: CachePage,
});
