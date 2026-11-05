import { createFileRoute } from "@tanstack/react-router";

import { ServicesPage } from "@/features/services";

function Page() {
  const { policyReadOnly } = Route.useRouteContext();
  return <ServicesPage readOnly={policyReadOnly} />;
}

export const Route = createFileRoute("/_authenticated/filtering/services")({
  component: Page,
});
