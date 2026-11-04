import { createFileRoute } from "@tanstack/react-router";

import { SettingsPage } from "@/features/settings";

function Page() {
  const { policyReadOnly } = Route.useRouteContext();
  return <SettingsPage readOnly={policyReadOnly} />;
}

export const Route = createFileRoute("/_authenticated/settings")({
  component: Page,
});
