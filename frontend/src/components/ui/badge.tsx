import { CircleAlert, CircleCheck, CircleSlash, Clock, type LucideIcon } from "lucide-react";
import type { ReactNode } from "react";

import { cn } from "@/lib/utils";

const tones = {
  neutral: { className: "bg-surface-muted text-text-secondary", icon: null },
  success: { className: "bg-success-soft text-success", icon: CircleCheck },
  warning: { className: "bg-warning-soft text-warning", icon: Clock },
  danger: { className: "bg-danger-soft text-danger", icon: CircleSlash },
  error: { className: "bg-danger-soft text-danger", icon: CircleAlert },
} satisfies Record<string, { className: string; icon: LucideIcon | null }>;

/** Status always pairs its color with an icon and text, so it never relies on color alone. */
export function Badge({ tone = "neutral", children }: { tone?: keyof typeof tones; children: ReactNode }) {
  const { className, icon: Icon } = tones[tone];
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs font-medium whitespace-nowrap",
        className,
      )}
    >
      {Icon && <Icon aria-hidden className="size-3" />}
      {children}
    </span>
  );
}
