import { createFileRoute } from "@tanstack/react-router";

import { RulesPage } from "@/features/rules";

function Page() {
  const { policyReadOnly } = Route.useRouteContext();
  return <RulesPage readOnly={policyReadOnly} />;
}

export const Route = createFileRoute("/_authenticated/filtering/rules")({
  component: Page,
});
