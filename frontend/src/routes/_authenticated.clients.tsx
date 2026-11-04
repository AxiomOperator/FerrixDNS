import { createFileRoute } from "@tanstack/react-router";

import { ClientsPage } from "@/features/clients";

function Page() {
  const { policyReadOnly } = Route.useRouteContext();
  return <ClientsPage readOnly={policyReadOnly} />;
}

export const Route = createFileRoute("/_authenticated/clients")({
  component: Page,
});
