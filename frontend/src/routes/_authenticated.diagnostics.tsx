import { createFileRoute } from "@tanstack/react-router";
import { z } from "zod";

import { DiagnosticsPage } from "@/features/diagnostics";

const searchSchema = z.object({
  name: z.string().optional().catch(undefined),
  type: z.string().optional().catch(undefined),
  client: z.string().optional().catch(undefined),
});

export const Route = createFileRoute("/_authenticated/diagnostics")({
  validateSearch: searchSchema,
  component: DiagnosticsPage,
});
