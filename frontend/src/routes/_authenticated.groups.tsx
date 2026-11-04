import { createFileRoute } from "@tanstack/react-router";

import { GroupsPage } from "@/features/groups";

function Page() {
  const { policyReadOnly } = Route.useRouteContext();
  return <GroupsPage readOnly={policyReadOnly} />;
}

export const Route = createFileRoute("/_authenticated/groups")({
  component: Page,
});
