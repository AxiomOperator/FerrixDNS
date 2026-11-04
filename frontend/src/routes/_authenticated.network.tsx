import { createFileRoute } from "@tanstack/react-router";

import { NetworkPage } from "@/features/network";

function Page() {
  const { policyReadOnly } = Route.useRouteContext();
  return <NetworkPage readOnly={policyReadOnly} />;
}

export const Route = createFileRoute("/_authenticated/network")({
  component: Page,
});
