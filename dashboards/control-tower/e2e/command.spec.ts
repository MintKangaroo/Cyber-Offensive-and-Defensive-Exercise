import { test, expect } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { setup, now } from "./fixtures";
import { parse } from "yaml";
test("overview, evidence inspector and keyboard command palette", async ({
  page,
}) => {
  await setup(page);
  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: "Overview", exact: true }),
  ).toBeVisible();
  await expect(page.locator(".sector-node")).toHaveCount(11);
  await page.screenshot({
    path: "../../docs/images/command-overview.png",
    fullPage: true,
  });
  await page
    .getByRole("button", { name: /Power grid.*Inspect sector/ })
    .click();
  await expect(page.getByRole("dialog")).toBeVisible();
  await expect(page.getByText("Training setpoint exercise")).toBeVisible();
  await page.keyboard.press("Escape");
  await page.keyboard.press("Control+k");
  await expect(
    page.getByRole("dialog", { name: "Command palette & global search" }),
  ).toBeVisible();
  await page
    .getByPlaceholder("Search authorized entities…")
    .fill("SCADA investigation");
  await expect(
    page.getByRole("button", { name: /SCADA investigation/ }),
  ).toBeVisible();
  await page.keyboard.press("ArrowDown");
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(/#challenges\/ICS-TRAINING/);
});
test("event virtualization, filtering after scroll, pause and inspect", async ({
  page,
}) => {
  await setup(page, { count: 5000 });
  await page.goto("/#events");
  await expect(page.locator(".virtual-event")).toHaveCount(18);
  await page.locator(".virtual-events").evaluate((el) => {
    el.scrollTop = 100000;
  });
  await page.getByLabel("Search evidence").fill("event-4999");
  await expect(page.locator(".virtual-event")).toHaveCount(1);
  await expect(page.locator(".virtual-event")).toBeInViewport();
  await page.getByRole("button", { name: "Pause view", exact: true }).click();
  await expect(
    page.getByText("The visible list is paused.", { exact: false }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Inspect event event-4999" }).click();
  await expect(page.locator(".raw-payload")).toContainText("event-4999");
});
test("incident transition needs explicit evidence and updates the lifecycle", async ({
  page,
}) => {
  const updates = await setup(page);
  await page.goto("/#incidents/INC-1");
  await expect(
    page.getByRole("heading", { name: "Unexpected SCADA setpoint change" }),
  ).toBeVisible();
  await page
    .getByRole("button", { name: "Move to triage", exact: true })
    .click();
  const dialog = page.getByRole("dialog");
  await expect(
    dialog.getByRole("button", { name: "Confirm transition" }),
  ).toBeDisabled();
  await dialog
    .getByLabel("Evidence / reason")
    .fill("Verified authorized exercise setpoint evidence");
  await dialog.getByRole("button", { name: "Confirm transition" }).click();
  await expect(dialog).toBeHidden();
  await expect(
    page.getByRole("button", { name: "Move to contained" }),
  ).toBeVisible();
  expect(updates[0]).toMatchObject({
    path: "/incidents/INC-1/transition",
    body: {
      value: "triage",
      note: "Verified authorized exercise setpoint evidence",
    },
  });
});
test("visual ↔ YAML does not rewrite source; validate gates publication", async ({
  page,
}) => {
  await setup(page);
  await page.goto("/#studio");
  await page.getByRole("button", { name: "YAML source", exact: true }).click();
  const editor = page.getByLabel("Scenario YAML source");
  const original = await editor.inputValue();
  await editor.fill(original + "  vendor_extension: {training: true}\n");
  const source = await editor.inputValue();
  await page
    .getByRole("button", { name: "Visual editor", exact: true })
    .click();
  await page.getByRole("button", { name: "YAML source", exact: true }).click();
  await expect(editor).toHaveValue(source);
  await expect(
    page.getByRole("button", { name: "Publish scenario", exact: true }),
  ).toBeDisabled();
  await page.getByRole("button", { name: "Validate & dry run" }).click();
  await expect(
    page.getByRole("button", { name: "Publish scenario", exact: true }),
  ).toBeEnabled();
});
test("crossover phases and investigation keys survive visual source switching", async ({
  page,
}) => {
  const updates = await setup(page);
  await page.goto("/#studio");
  await page.getByRole("button", { name: "New crossover draft" }).click();
  await expect(page.getByLabel("New phase unlock condition")).toHaveValue(
    "phase_1_operations.completed",
  );
  await page.getByRole("button", { name: "Add phase", exact: true }).click();
  const objective = page.getByRole("group", {
    name: "phase_2_investigation objective 1",
    exact: true,
  });
  await objective
    .getByLabel("Objective name", { exact: true })
    .fill("Identify recovery evidence");
  await objective
    .getByLabel("Instructor answer key")
    .fill("verified local event");
  await objective.getByLabel("Objective points").fill("35");
  await page.getByRole("button", { name: "YAML source", exact: true }).click();
  const editor = page.getByLabel("Scenario YAML source");
  const original = await editor.inputValue();
  const raw = parse(original).crossover_scenario;
  expect(raw.phase_2_investigation).toMatchObject({
    actor: "blue",
    locked_until: "phase_1_operations.completed",
    objectives: [
      {
        name: "Identify recovery evidence",
        points: 35,
        answer: "verified local event",
      },
    ],
  });
  expect(raw.phase_1_operations.stages[0].stage).toBe(1);
  await page
    .getByRole("button", { name: "Visual editor", exact: true })
    .click();
  await page.getByRole("button", { name: "YAML source", exact: true }).click();
  await expect(editor).toHaveValue(original);
  await page.getByRole("button", { name: "Validate & dry run" }).click();
  await expect(
    page.getByRole("button", { name: "Publish scenario", exact: true }),
  ).toBeEnabled();
  expect(updates.find((u) => u.path === "/scenarios/validate")?.body.yaml).toBe(
    original,
  );
});

test("unapplied evidence blocks save and mode changes; keyboard applies typed criteria", async ({
  page,
}) => {
  await setup(page);
  await page.goto("/#studio");
  const editor = page.getByLabel("Stage evidence criteria", { exact: true });
  await editor.fill('{"metadata.rpm":');
  await expect(
    page.getByRole("button", { name: "Save draft", exact: true }),
  ).toBeDisabled();
  await expect(
    page.getByRole("button", { name: "Validate & dry run" }),
  ).toBeDisabled();
  await expect(
    page.getByRole("button", { name: "YAML source", exact: true }),
  ).toBeDisabled();
  await page
    .getByRole("button", { name: "Apply stage evidence criteria" })
    .click();
  await expect(page.getByRole("alert")).toBeVisible();
  await editor.fill('{"metadata.rpm": 1200, "metadata.verified": true}');
  const apply = page.getByRole("button", {
    name: "Apply stage evidence criteria",
  });
  await apply.focus();
  await page.keyboard.press("Enter");
  await expect(
    page.getByRole("button", { name: "Save draft", exact: true }),
  ).toBeEnabled();
  await page.getByRole("button", { name: "YAML source", exact: true }).click();
  const raw = parse(
    await page.getByLabel("Scenario YAML source").inputValue(),
  ).scenario;
  expect(raw.stages[0].match).toEqual({
    "metadata.rpm": 1200,
    "metadata.verified": true,
  });
});

test("crossover authoring remains accessible and usable at tablet width", async ({
  page,
}) => {
  await setup(page);
  await page.setViewportSize({ width: 820, height: 1180 });
  await page.goto("/#studio");
  await page.getByRole("button", { name: "New crossover draft" }).click();
  await page.getByRole("button", { name: "Add phase", exact: true }).click();
  const accessibility = await new AxeBuilder({ page })
    .include(".studio")
    .withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"])
    .analyze();
  expect(accessibility.violations).toEqual([]);
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
});

test("replay scrubbing synchronizes asset evidence and score", async ({
  page,
}) => {
  await setup(page);
  await page.goto("/#replay");
  await expect(
    page.getByRole("slider", { name: "Scrub exercise timeline" }),
  ).toBeVisible();
  const asset = page
    .locator(".replay-asset")
    .filter({ hasText: "Power grid / SCADA" });
  await expect(asset).toContainText("Attack observed");
  await page
    .getByRole("slider", { name: "Scrub exercise timeline" })
    .fill(String(now + 45));
  await expect(asset).toContainText("Compromised");
  await expect(
    page.getByRole("table", { name: "Historical score ledger totals" }),
  ).toContainText("25");
  await page.getByRole("button", { name: "Next recovery" }).click();
  await expect(asset).toContainText("Recovered");
});
test("observer has no instructor or SOC navigation and deep links fail closed", async ({
  page,
}) => {
  await setup(page, { role: "observer" });
  await page.goto("/#control");
  await expect(page.getByText("Workspace not authorized")).toBeVisible();
  await expect(
    page.getByRole("link", { name: "Safety controls", exact: true }),
  ).toHaveCount(0);
  await expect(
    page.getByRole("link", { name: "SIEM", exact: true }),
  ).toHaveCount(0);
});
test("degraded sources remain explicit", async ({ page }) => {
  await setup(page, { degraded: true });
  await page.goto("/");
  await expect(page.locator(".degraded-banner")).toContainText(
    "1 source is unavailable",
  );
  await expect(page.getByText("Health has not been measured")).toBeVisible();
});
test("mobile instructor emergency confirmation fits and stays keyboard accessible", async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 844 });
  const updates = await setup(page);
  await page.goto("/#safety");
  await expect(
    page.getByRole("heading", { name: "Safety controls", exact: true }),
  ).toBeVisible();
  await expect(page.locator("body")).toHaveJSProperty("scrollWidth", 390);
  await page.getByRole("button", { name: /Emergency stop/i }).click();
  const dialog = page.getByRole("dialog");
  await expect(dialog).toBeVisible();
  expect(updates).toHaveLength(0);
  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();
});
test("overview and incident workbench meet automated WCAG checks", async ({
  page,
}) => {
  await setup(page);
  for (const path of ["/#overview", "/#incidents/INC-1"]) {
    await page.goto(path);
    await expect(
      page
        .locator(".sector-node")
        .first()
        .or(
          page.getByRole("heading", {
            name: "Unexpected SCADA setpoint change",
          }),
        ),
    ).toBeVisible();
    const results = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"])
      .analyze();
    expect(results.violations).toEqual([]);
  }
});
test("login remains usable with reduced motion and missing telemetry", async ({
  page,
}) => {
  await setup(page, { unauthenticated: true });
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.goto("/");
  await expect(
    page.getByRole("button", { name: "Enter command platform" }),
  ).toBeVisible();
  const result = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"])
    .analyze();
  expect(result.violations).toEqual([]);
});
test("cancelling a completed safety confirmation does not send an action", async ({
  page,
}) => {
  const updates = await setup(page);
  await page.goto("/#safety");
  await page
    .getByRole("button", { name: "Emergency stop", exact: true })
    .click();
  await page
    .getByLabel("Required audit reason")
    .fill("Reviewed training safety checkpoint");
  await page.getByRole("button", { name: "Cancel", exact: true }).click();
  await expect(page.getByRole("dialog")).toBeHidden();
  expect(updates).toHaveLength(0);
});

test("replay loads subsequent pages before enabling synchronized playback", async ({
  page,
}) => {
  await setup(page);
  let pages = 0;
  await page.route(/\/command\/replay(?:\/page)?(?:\?|$)/, async (route) => {
    const url = new URL(route.request().url());
    const event = (id: string, offset: number, type: string) => ({
      event_id: id,
      timestamp: now + offset,
      event_type: type,
      actor: "red",
      team_id: "team-blue",
      scenario_id: "TRAINING-01",
      target_asset: "power_plant",
      metadata: {},
    });
    const source = (data: unknown) => ({
      status: "ready",
      source: "test",
      data,
      observed_at: now,
    });
    const body = url.pathname.endsWith("/page")
      ? (pages++,
        {
          events: [event("last-page-recovery", 300, "asset_recovered")],
          next_cursor: "",
          complete: true,
        })
      : {
          sources: {
            events: source({
              events: [event("first-page-compromise", 0, "asset_compromised")],
              next_cursor: "fixture-cursor",
            }),
            scores: source({ achievements: [] }),
            incidents: source({ incidents: [] }),
          },
          limits: [],
        };
    await route.fulfill({ json: body });
  });
  await page.goto("/#replay");
  const slider = page.getByRole("slider", { name: "Scrub exercise timeline" });
  await expect(slider).toHaveAttribute("max", String(now + 300));
  expect(pages).toBe(1);
  await slider.fill(String(now + 300));
  await expect(
    page.locator(".replay-asset").filter({ hasText: "Power grid / SCADA" }),
  ).toContainText("Recovered");
});

test("personal training distinguishes observed attempts and records an explicit start", async ({
  page,
}) => {
  await setup(page, { role: "red" });
  let starts = 0;
  await page.route("**/command/training", (route) =>
    route.fulfill({
      json: {
        scope: "team",
        individual: {
          status: "ready",
          data: {
            scope: "individual",
            collection_enabled: true,
            method: "Recorded personal grader results in this exercise.",
            domains: [
              { domain: "ICS/OT", available: 2, completed: 1, proficiency: 50 },
            ],
            activity: [
              {
                id: "ICS-TRAINING",
                title: "Observed range recovery",
                attempts: 2,
                completed: true,
                elapsed_sec: 60,
              },
            ],
            recommendations: [
              {
                id: "ICS-NEXT",
                title: "Next range exercise",
                difficulty: "easy",
                reason: "No recorded personal completion",
              },
            ],
            unavailable_inputs: ["hint count", "response quality"],
          },
        },
      },
    }),
  );
  await page.route("**/command/training/challenges/ICS-NEXT/start", (route) => {
    starts++;
    return route.fulfill({ json: { started_at: now } });
  });
  await page.goto("/#training");
  await expect(
    page.getByText("Personal exercise evidence", { exact: false }),
  ).toBeVisible();
  const table = page.getByRole("table", { name: "Personal training evidence" });
  await expect(table).toContainText("Observed range recovery");
  await expect(table).toContainText("Grader passed");
  await expect(
    page.getByText("Unavailable measurements:", { exact: false }),
  ).toContainText("hint count");
  expect(starts).toBe(0);
  await page.getByRole("button", { name: /Next range exercise/ }).click();
  await expect(page).toHaveURL(/#challenges\/ICS-NEXT/);
  expect(starts).toBe(1);
});

test("training keeps team evidence explicit when the personal source is unavailable", async ({
  page,
}) => {
  await setup(page, { role: "red" });
  await page.route("**/command/training", (route) =>
    route.fulfill({
      json: {
        scope: "team",
        domains: [],
        recommendations: [],
        individual: { status: "unavailable", data: null },
      },
    }),
  );
  await page.goto("/#training");
  await expect(
    page.getByText("Team completion evidence", { exact: false }),
  ).toBeVisible();
  await expect(
    page.getByText("Individual evidence is unavailable", { exact: false }),
  ).toBeVisible();
  await expect(
    page.getByRole("table", { name: "Personal training evidence" }),
  ).toHaveCount(0);
});
