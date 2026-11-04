import { createFileRoute } from "@tanstack/react-router";

import { ForwardersPage } from "@/features/forwarders";

function Page() {
  const { policyReadOnly } = Route.useRouteContext();
  return <ForwardersPage readOnly={policyReadOnly} />;
}

export const Route = createFileRoute("/_authenticated/dns/forwarders")({
  component: Page,
});
