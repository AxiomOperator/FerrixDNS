import { Switch as RadixSwitch } from "radix-ui";

export function Switch({
  checked,
  onCheckedChange,
  label,
  disabled,
}: {
  checked: boolean;
  onCheckedChange: (checked: boolean) => void;
  label: string;
  disabled?: boolean;
}) {
  return (
    <RadixSwitch.Root
      checked={checked}
      onCheckedChange={onCheckedChange}
      aria-label={label}
      disabled={disabled}
      className="relative h-5 w-9 shrink-0 cursor-pointer rounded-full border border-border-strong bg-surface-muted transition-colors disabled:cursor-not-allowed disabled:opacity-50 data-[state=checked]:border-accent data-[state=checked]:bg-accent"
    >
      <RadixSwitch.Thumb className="block size-3.5 translate-x-0.5 rounded-full bg-text-secondary transition-transform data-[state=checked]:translate-x-[18px] data-[state=checked]:bg-accent-text" />
    </RadixSwitch.Root>
  );
}
