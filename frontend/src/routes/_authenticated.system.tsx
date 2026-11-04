import { createFileRoute } from "@tanstack/react-router";

import { SystemPage } from "@/features/system";

function Page() {
  const { policyReadOnly } = Route.useRouteContext();
  return <SystemPage readOnly={policyReadOnly} />;
}

export const Route = createFileRoute("/_authenticated/system")({
  component: Page,
});
