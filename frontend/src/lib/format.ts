import { format, formatDistanceToNowStrict } from "date-fns";

export function formatCount(value: number): string {
  return new Intl.NumberFormat().format(value);
}

export function formatTime(iso: string): string {
  return format(new Date(iso), "MMM d, HH:mm:ss");
}

export function formatDateTime(iso: string): string {
  return format(new Date(iso), "MMM d, yyyy HH:mm");
}

export function timeAgo(iso: string): string {
  return `${formatDistanceToNowStrict(new Date(iso))} ago`;
}

export function formatDuration(microseconds: number): string {
  if (microseconds < 1000) return `${microseconds} µs`;
  const milliseconds = microseconds / 1000;
  return milliseconds < 100 ? `${milliseconds.toFixed(1)} ms` : `${Math.round(milliseconds)} ms`;
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let value = bytes;
  let unit = -1;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(value < 10 ? 1 : 0)} ${units[unit]}`;
}

export function formatSeconds(seconds: number): string {
  if (seconds < 60) return `${seconds} seconds`;
  if (seconds < 3600) return `${Math.round(seconds / 60)} minutes`;
  if (seconds < 86_400) return `${Math.round(seconds / 3600)} hours`;
  return `${Math.round(seconds / 86_400)} days`;
}

export function shortRevision(revision: string): string {
  return revision.slice(0, 12);
}
