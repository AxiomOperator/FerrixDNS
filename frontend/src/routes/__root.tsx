import type { QueryClient } from "@tanstack/react-query";
import { Link, Outlet, createRootRouteWithContext } from "@tanstack/react-router";

function NotFound() {
  return (
    <main className="flex min-h-dvh flex-col items-center justify-center gap-2 p-4 text-center">
      <h1 className="text-lg font-semibold">Page not found</h1>
      <Link to="/" className="text-sm font-medium text-accent underline">
        Go to the overview
      </Link>
    </main>
  );
}

export const Route = createRootRouteWithContext<{ queryClient: QueryClient }>()({
  component: Outlet,
  notFoundComponent: NotFound,
});
