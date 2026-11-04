import { useQuery } from "@tanstack/react-query";
import { Pause, Play } from "lucide-react";
import { type FormEvent, useEffect, useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Field, Input } from "@/components/ui/form";
import { api, queries, usePolicyMutation } from "@/lib/api/hooks";

const PRESETS = [
  { label: "5 minutes", seconds: 300 },
  { label: "30 minutes", seconds: 1800 },
  { label: "1 hour", seconds: 3600 },
  { label: "4 hours", seconds: 14_400 },
];

const MAX_MINUTES = 1440;

function formatRemaining(seconds: number): string {
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const rest = seconds % 60;
  if (hours > 0) return `${hours}h ${minutes}m`;
  if (minutes > 0) return `${minutes}m ${String(rest).padStart(2, "0")}s`;
  return `${rest}s`;
}

/** Whole seconds until a time, updated once a second. */
function useSecondsUntil(until: string | null | undefined): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!until) return;
    setNow(Date.now());
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, [until]);
  if (!until) return 0;
  return Math.max(0, Math.ceil((new Date(until).getTime() - now) / 1000));
}

export function BlockingControl() {
  const blocking = useQuery(queries.blocking());
  const [dialogOpen, setDialogOpen] = useState(false);
  const [minutes, setMinutes] = useState("15");
  const pause = usePolicyMutation(
    (seconds: number) => api.pauseBlocking({ seconds }),
    "Blocking paused",
  );
  const resume = usePolicyMutation(() => api.resumeBlocking(), "Blocking resumed");
  const remaining = useSecondsUntil(blocking.data?.paused_until);

  function choose(seconds: number) {
    pause.mutate(seconds, { onSuccess: () => setDialogOpen(false) });
  }

  function submit(event: FormEvent) {
    event.preventDefault();
    choose(Math.round(Number(minutes) * 60));
  }

  if (blocking.data?.paused && remaining > 0) {
    return (
      <div className="flex min-w-0 items-center gap-2">
        <span role="status" className="flex min-w-0 items-center gap-2">
          <Badge tone="warning">
            <span className="sr-only sm:not-sr-only">Blocking paused</span>
            <span aria-hidden className="sm:hidden">
              Paused
            </span>
          </Badge>
          <span className="shrink-0 whitespace-nowrap text-sm tabular-nums text-text-secondary">
            {formatRemaining(remaining)}
            <span className="sr-only"> left</span>
          </span>
        </span>
        <Button size="sm" disabled={resume.isPending} onClick={() => resume.mutate(undefined)}>
          <Play aria-hidden className="size-3.5" />
          Resume
        </Button>
      </div>
    );
  }

  return (
    <>
      <Button variant="ghost" size="sm" onClick={() => setDialogOpen(true)}>
        <Pause aria-hidden className="size-3.5" />
        Pause blocking
      </Button>
      <Dialog
        open={dialogOpen}
        onOpenChange={setDialogOpen}
        title="Pause blocking"
        description="Every device can reach blocked domains until the time is up, then blocking comes back on its own. Emergency rules stay on, and restarting the node ends a pause."
      >
        <div className="grid grid-cols-2 gap-2">
          {PRESETS.map((preset) => (
            <Button key={preset.seconds} disabled={pause.isPending} onClick={() => choose(preset.seconds)}>
              {preset.label}
            </Button>
          ))}
        </div>
        <form className="mt-4 flex items-end gap-2" onSubmit={submit}>
          <div className="flex-1">
            <Field label="Other time (minutes)" htmlFor="pause-minutes">
              <Input
                id="pause-minutes"
                type="number"
                min={1}
                max={MAX_MINUTES}
                required
                value={minutes}
                onChange={(event) => setMinutes(event.target.value)}
              />
            </Field>
          </div>
          <Button type="submit" variant="primary" disabled={pause.isPending}>
            Pause
          </Button>
        </form>
      </Dialog>
    </>
  );
}
