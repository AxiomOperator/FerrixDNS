import type { ButtonHTMLAttributes, Ref } from "react";

import { cn } from "@/lib/utils";

const variants = {
  primary: "bg-accent text-accent-text hover:opacity-90",
  secondary: "border border-border-strong bg-surface text-text hover:bg-surface-muted",
  ghost: "text-text-secondary hover:bg-surface-muted hover:text-text",
  danger: "bg-danger text-danger-text hover:opacity-90",
};

const sizes = {
  md: "h-9 px-3 text-sm",
  sm: "h-8 px-2.5 text-xs",
  icon: "size-8",
};

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: keyof typeof variants;
  size?: keyof typeof sizes;
  ref?: Ref<HTMLButtonElement>;
}

export function Button({ variant = "secondary", size = "md", className, type, ...props }: ButtonProps) {
  return (
    <button
      type={type ?? "button"}
      className={cn(
        "inline-flex shrink-0 cursor-pointer items-center justify-center gap-1.5 rounded-md font-medium whitespace-nowrap transition-colors disabled:cursor-not-allowed disabled:opacity-50",
        variants[variant],
        sizes[size],
        className,
      )}
      {...props}
    />
  );
}
