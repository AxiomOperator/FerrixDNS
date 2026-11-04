import { CircleAlert, Lock } from "lucide-react";
import type { ReactNode } from "react";

import { Button } from "./ui/button";

import { ApiError, errorMessage } from "@/lib/api/client";

export function PageHeader({
  title,
  description,
  actions,
}: {
  title: string;
  description?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
      <div className="min-w-0">
        <h1 className="text-xl font-semibold">{title}</h1>
        {description && <p className="mt-0.5 text-sm text-text-muted">{description}</p>}
      </div>
      {actions}
    </div>
  );
}

export function Loading({ label = "Loading…" }: { label?: string }) {
  return (
    <p role="status" className="px-4 py-8 text-center text-sm text-text-muted">
      {label}
    </p>
  );
}

export function ErrorState({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const requestId = error instanceof ApiError ? error.requestId : undefined;
  return (
    <div role="alert" className="flex flex-col items-center gap-2 px-4 py-8 text-center">
      <CircleAlert aria-hidden className="size-5 text-danger" />
      <p className="text-sm font-medium">{errorMessage(error)}</p>
      {requestId && <p className="text-xs text-text-muted">Request ID: {requestId}</p>}
      {onRetry && (
        <Button size="sm" onClick={onRetry}>
          Try again
        </Button>
      )}
    </div>
  );
}

export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="px-4 py-10 text-center">
      <p className="text-sm font-medium">{title}</p>
      {children && <div className="mt-1 text-sm text-text-muted">{children}</div>}
    </div>
  );
}

export function ReadOnlyNotice() {
  return (
    <div className="mb-4 flex items-start gap-2 rounded-lg border border-border bg-warning-soft px-3 py-2 text-sm text-warning">
      <Lock aria-hidden className="mt-0.5 size-4 shrink-0" />
      <p>
        This node&apos;s policy comes from a file, so editing is turned off here. Change the file and
        send SIGHUP, or restart without <code>--policy</code> to manage policy in this dashboard.
      </p>
    </div>
  );
}
