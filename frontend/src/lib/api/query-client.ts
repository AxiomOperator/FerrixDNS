import { QueryClient } from "@tanstack/react-query";

import { ApiError } from "./client";

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 5_000,
      // Query logs are sensitive, so they don't linger in memory after leaving a page.
      gcTime: 60_000,
      retry: (failures, error) => {
        // Retrying can't fix a client error.
        if (error instanceof ApiError && error.status >= 400 && error.status < 500) return false;
        return failures < 2;
      },
    },
  },
});
