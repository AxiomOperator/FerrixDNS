import { createFileRoute } from "@tanstack/react-router";

import { ListsPage } from "@/features/lists";

function Page() {
  const { policyReadOnly } = Route.useRouteContext();
  return <ListsPage readOnly={policyReadOnly} />;
}

export const Route = createFileRoute("/_authenticated/filtering/lists")({
  component: Page,
});
