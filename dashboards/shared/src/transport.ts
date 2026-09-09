export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}
export type JsonObject = Record<string, unknown>;
export function object(value: unknown): JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as JsonObject)
    : {};
}
export function objects(value: unknown): JsonObject[] {
  return Array.isArray(value)
    ? (value.filter(
        (v) => v && typeof v === "object" && !Array.isArray(v),
      ) as JsonObject[])
    : [];
}
export function str(value: unknown, fallback = ""): string {
  return typeof value === "string" ? value : fallback;
}
export function num(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}
export function createClient(base: string, token: () => string = () => "") {
  return async function request<T = JsonObject>(
    path: string,
    init: RequestInit & { timeoutMs?: number } = {},
  ): Promise<T> {
    if (!path.startsWith("/") || path.startsWith("//"))
      throw new Error("API path must be relative to the configured service");
    const controller = new AbortController();
    const cancel = () => controller.abort();
    init.signal?.addEventListener("abort", cancel, { once: true });
    if (init.signal?.aborted) controller.abort();
    const timeout = setTimeout(cancel, init.timeoutMs ?? 15000);
    const headers = new Headers(init.headers);
    if (init.body && !(init.body instanceof FormData))
      headers.set("Content-Type", "application/json");
    const bearer = token();
    if (bearer) headers.set("Authorization", `Bearer ${bearer}`);
    try {
      const response = await fetch(`${base}${path}`, {
        ...init,
        headers,
        credentials: "include",
        signal: controller.signal,
        redirect: "error",
      });
      if (!response.ok) {
        let message = `Request failed (${response.status})`;
        try {
          const body: unknown = await response.json();
          const detail = object(body).detail;
          if (typeof detail === "string") message = detail;
        } catch {
          /* don't render arbitrary server HTML */
        }
        throw new ApiError(response.status, message);
      }
      if (response.status === 204) return undefined as T;
      if (!response.headers.get("content-type")?.includes("application/json"))
        throw new ApiError(502, "Service returned an unexpected response");
      return (await response.json()) as T;
    } finally {
      clearTimeout(timeout);
      init.signal?.removeEventListener("abort", cancel);
    }
  };
}
export interface SSEFrame {
  id: string;
  topic: string;
  data: string;
}
/** Incremental WHATWG-style SSE framing. Handles UTF-8 in decoder, CRLF and multiline data. */
export class SSEParser {
  private buffer = "";
  private lines: string[] = [];
  private frameSize = 0;
  constructor(private emit: (frame: SSEFrame) => void) {}
  push(chunk: string) {
    this.buffer += chunk;
    if (this.buffer.length > 1024 * 1024)
      throw new Error("Stream frame exceeds limit");
    let newline: number;
    while ((newline = this.buffer.indexOf("\n")) >= 0) {
      const line = this.buffer.slice(0, newline).replace(/\r$/, "");
      this.buffer = this.buffer.slice(newline + 1);
      if (line) {
        this.frameSize += line.length;
        if (this.frameSize > 1024 * 1024)
          throw new Error("Stream frame exceeds limit");
        this.lines.push(line);
        if (this.lines.length > 10000)
          throw new Error("Stream frame exceeds line limit");
        continue;
      }
      let id = "",
        topic = "message";
      const data: string[] = [];
      for (const field of this.lines) {
        if (field.startsWith(":")) continue;
        const colon = field.indexOf(":");
        const key = colon < 0 ? field : field.slice(0, colon);
        const val = colon < 0 ? "" : field.slice(colon + 1).replace(/^ /, "");
        if (key === "id" && !val.includes("\0")) id = val;
        if (key === "event") topic = val;
        if (key === "data") data.push(val);
      }
      this.lines = [];
      this.frameSize = 0;
      if (data.length) this.emit({ id, topic, data: data.join("\n") });
    }
  }
}
export const nextBackoff = (attempt: number) =>
  Math.min(30000, 1000 * 2 ** Math.min(5, attempt));
