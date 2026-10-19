/**
 * 접근성 회귀(axe, 구조). jsdom 레이아웃이 없어 color-contrast 는 수동 감사로 이관.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, act, fireEvent, screen } from "@testing-library/react";
import axe from "axe-core";

vi.mock("./api", () => ({
  fetchPowerTelemetry: vi.fn().mockResolvedValue(null),
  powerRegistersFromTelemetry: vi.fn(),
  executeStrike: vi.fn().mockResolvedValue(false),
  subscribeStream: vi.fn().mockReturnValue(() => {}),
}));

import App from "./App";

beforeEach(() => vi.clearAllMocks());

async function renderAndAxe(setup?: () => Promise<void>) {
  let container!: HTMLElement;
  await act(async () => {
    ({ container } = render(<App />));
    await new Promise((r) => setTimeout(r, 0));
  });
  if (setup) await setup();
  const results = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
  expect(results.violations.map((v) => `${v.id}: ${v.help}`)).toEqual([]);
}

describe("Live-Fire Ops accessibility (axe, structural)", () => {
  it("현황 아레나 — axe 위반 없음", () => renderAndAxe());
  it("시설 작전 콘솔 — axe 위반 없음", () =>
    renderAndAxe(async () => {
      await act(async () => {
        fireEvent.click(screen.getByRole("button", { name: /발전소 SIS/ }));
      });
    }));
});
