import { describe, it, expect, vi, afterEach } from "vitest";
import {
  render,
  screen,
  fireEvent,
  renderHook,
  waitFor,
} from "@testing-library/react";
import {
  Button,
  Dialog,
  StatusBadge,
  ErrorState,
} from "@cyber-range/command-system";
import { useCommandData } from "./useCommandData";
import type { Session } from "./api";
const session: Session = {
  actor: "test",
  role: "instructor",
  team_id: "",
  match_id: "",
  capabilities: ["events"],
  observer_delay_sec: 30,
};
afterEach(() => vi.unstubAllGlobals());
describe("critical command primitives", () => {
  it("cancel and incidental buttons never submit a confirmation form", () => {
    const submit = vi.fn((e) => e.preventDefault());
    render(
      <form onSubmit={submit}>
        <Button>Cancel</Button>
        <Button type="submit">Confirm</Button>
      </form>,
    );
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(submit).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Confirm" }));
    expect(submit).toHaveBeenCalledOnce();
  });
  it("status includes text and a shape rather than color alone", () => {
    render(<StatusBadge tone="critical">Critical incident</StatusBadge>);
    expect(screen.getByText("Critical incident")).toBeVisible();
    expect(screen.getByText("!")).toHaveAttribute("aria-hidden", "true");
  });
  it("errors are announced and expose retry", () => {
    const retry = vi.fn();
    render(<ErrorState message="Source disconnected" retry={retry} />);
    expect(screen.getByRole("alert")).toHaveTextContent("Source disconnected");
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(retry).toHaveBeenCalledOnce();
  });
  it("dialog restores focus to the invoking control on close", () => {
    HTMLDialogElement.prototype.showModal = function () {
      this.open = true;
    };
    HTMLDialogElement.prototype.close = function () {
      this.open = false;
    };
    const trigger = document.createElement("button");
    document.body.append(trigger);
    trigger.focus();
    const { unmount } = render(
      <Dialog title="Confirm action" onClose={() => {}}>
        <input aria-label="Audit reason" />
      </Dialog>,
    );
    expect(screen.getByRole("dialog")).toHaveAccessibleName("Confirm action");
    unmount();
    expect(trigger).toHaveFocus();
    trigger.remove();
  });
});
describe("live subscription lifecycle", () => {
  it("stops unauthorized streams without treating them as empty success", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) =>
        url.includes("/stream")
          ? new Response("", { status: 403 })
          : new Response(JSON.stringify({ sources: {}, assets: [] }), {
              headers: { "content-type": "application/json" },
            }),
      ),
    );
    const { result } = renderHook(() => useCommandData(session, "s"));
    await waitFor(() => expect(result.current.connection).toBe("unauthorized"));
  });
  it("observer reads delayed durable snapshots without opening privileged SSE", async () => {
    const fetcher = vi.fn(
      async () =>
        new Response(JSON.stringify({ sources: {}, assets: [] }), {
          headers: { "content-type": "application/json" },
        }),
    );
    vi.stubGlobal("fetch", fetcher);
    const { result } = renderHook(() =>
      useCommandData({ ...session, role: "observer" }, "s"),
    );
    await waitFor(() => expect(result.current.snapshot).not.toBeNull());
    expect(result.current.connection).toBe("delayed");
    expect(fetcher.mock.calls).toHaveLength(1);
  });
  it("aborts the subscription when leaving an exercise scope", async () => {
    let signal: AbortSignal | undefined;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, options: RequestInit) => {
        if (url.includes("/stream")) {
          signal = options.signal as AbortSignal;
          return new Promise<Response>(() => {});
        }
        return new Response(JSON.stringify({ sources: {}, assets: [] }), {
          headers: { "content-type": "application/json" },
        });
      }),
    );
    const { unmount } = renderHook(() => useCommandData(session, "s"));
    await waitFor(() => expect(signal).toBeDefined());
    unmount();
    expect(signal?.aborted).toBe(true);
  });
});
