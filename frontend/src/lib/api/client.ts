import type { components } from "./schema";

export type Schemas = components["schemas"];

/** A failed API request. `code` is stable, and `requestId` helps find it in the node's log. */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly requestId?: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

const BASE = "/api/v1";

let csrfToken: string | undefined;

export function setCsrfToken(token: string | undefined) {
  csrfToken = token;
}

let onUnauthenticated: () => void = () => undefined;

export function setUnauthenticatedHandler(handler: () => void) {
  onUnauthenticated = handler;
}

interface RequestOptions {
  body?: unknown;
  ifMatch?: number;
  signal?: AbortSignal;
}

export async function request<T>(
  method: string,
  path: string,
  options: RequestOptions = {},
): Promise<T> {
  const headers: Record<string, string> = {};
  if (options.body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET" && csrfToken) headers["X-CSRF-Token"] = csrfToken;
  if (options.ifMatch !== undefined) headers["If-Match"] = `"${options.ifMatch}"`;

  let response: Response;
  try {
    response = await fetch(`${BASE}${path}`, {
      method,
      headers,
      credentials: "same-origin",
      signal: options.signal,
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") throw error;
    throw new ApiError(0, "NETWORK_ERROR", "Can't reach the node. Check that it's still running.");
  }

  if (!response.ok) {
    const parsed = (await response.json().catch(() => undefined)) as
      | Schemas["ErrorEnvelope"]
      | undefined;
    const error = new ApiError(
      response.status,
      parsed?.error.code ?? "UNKNOWN_ERROR",
      parsed?.error.message ?? `The node responded with HTTP ${response.status}`,
      parsed?.error.request_id,
    );
    // Signing in is allowed to fail without treating the session as lost.
    if (response.status === 401 && !path.startsWith("/auth/")) onUnauthenticated();
    throw error;
  }
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

async function failure(response: Response): Promise<ApiError> {
  const parsed = (await response.json().catch(() => undefined)) as
    | Schemas["ErrorEnvelope"]
    | undefined;
  return new ApiError(
    response.status,
    parsed?.error.code ?? "UNKNOWN_ERROR",
    parsed?.error.message ?? `The node responded with HTTP ${response.status}`,
    parsed?.error.request_id,
  );
}

/** Downloads a backup, returning its content and suggested file name. */
export async function downloadBackup(): Promise<{ blob: Blob; fileName: string }> {
  const response = await fetch(`${BASE}/backup`, {
    method: "POST",
    credentials: "same-origin",
    headers: csrfToken ? { "X-CSRF-Token": csrfToken } : {},
  });
  if (!response.ok) throw await failure(response);
  const disposition = response.headers.get("Content-Disposition") ?? "";
  const fileName = /filename="([^"]+)"/.exec(disposition)?.[1] ?? "ferrixdns-backup.tar.gz";
  return { blob: await response.blob(), fileName };
}

/** Checks a backup file and, unless `dryRun` is set, restores it. */
export async function uploadBackup(
  file: File,
  dryRun: boolean,
): Promise<Schemas["RestoreResult"]> {
  const response = await fetch(`${BASE}/backup/restore?dry_run=${dryRun}`, {
    method: "POST",
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/gzip",
      ...(csrfToken ? { "X-CSRF-Token": csrfToken } : {}),
    },
    body: file,
  });
  if (!response.ok) throw await failure(response);
  const body = (await response.json()) as { data: Schemas["RestoreResult"] };
  return body.data;
}

/** Fetches a `{ data }` envelope and returns its contents. */
export async function getData<T>(path: string, signal?: AbortSignal): Promise<T> {
  const body = await request<{ data: T }>("GET", path, { signal });
  return body.data;
}

export async function sendData<T>(
  method: string,
  path: string,
  options: RequestOptions = {},
): Promise<T> {
  const body = await request<{ data: T }>(method, path, options);
  return body.data;
}

export function errorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    return error.requestId && error.status >= 500
      ? `${error.message} (request ${error.requestId})`
      : error.message;
  }
  return error instanceof Error ? error.message : "Something went wrong";
}
