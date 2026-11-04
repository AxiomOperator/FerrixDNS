import { createFileRoute } from "@tanstack/react-router";
import { z } from "zod";

import { QueriesPage } from "@/features/queries";

const searchSchema = z.object({
  qname: z.string().optional().catch(undefined),
  client: z.string().optional().catch(undefined),
  action: z.enum(["blocked", "forwarded", "cached", "local", "failed", "rejected"]).optional().catch(undefined),
  qtype: z.string().optional().catch(undefined),
});

function Page() {
  const { policyReadOnly } = Route.useRouteContext();
  return <QueriesPage readOnly={policyReadOnly} />;
}

export const Route = createFileRoute("/_authenticated/queries")({
  validateSearch: searchSchema,
  component: Page,
});
