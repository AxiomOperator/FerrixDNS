import { createFileRoute } from "@tanstack/react-router";

import { LocalDnsPage } from "@/features/local-dns";

function Page() {
  const { policyReadOnly } = Route.useRouteContext();
  return <LocalDnsPage readOnly={policyReadOnly} />;
}

export const Route = createFileRoute("/_authenticated/dns/records")({
  component: Page,
});
