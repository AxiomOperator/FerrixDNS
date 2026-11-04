import { createFileRoute } from "@tanstack/react-router";
import { z } from "zod";

import { SETTINGS_TABS, SettingsPage } from "@/features/settings";

const searchSchema = z.object({
  tab: z.enum(SETTINGS_TABS).optional().catch(undefined),
});

function Page() {
  const { policyReadOnly } = Route.useRouteContext();
  const { tab } = Route.useSearch();
  const navigate = Route.useNavigate();
  return (
    <SettingsPage
      readOnly={policyReadOnly}
      tab={tab ?? "blocking"}
      onTabChange={(next) => void navigate({ search: { tab: next }, replace: true })}
    />
  );
}

export const Route = createFileRoute("/_authenticated/settings")({
  validateSearch: searchSchema,
  component: Page,
});
