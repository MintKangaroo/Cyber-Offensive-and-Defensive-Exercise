import { expect, Page, test } from "@playwright/test";

const epoch = Date.parse("2026-07-30T00:00:00Z") / 1000;

function token(role: "competitor" | "operator" | "observer", teamId = "") {
  const encode = (value: object) => Buffer.from(JSON.stringify(value)).toString("base64url");
  return `${encode({ alg: "none" })}.${encode({
    role, team_id: teamId, match_id: "visual-match", tournament_id: "visual-cup",
  })}.fixture`;
}

const scores = [
  {
    rank: 1, team_id: "team-1", team: "Team 01", slug: "team-01",
    attack: 120, defense: 90, flag_defense: 0, availability: 95,
    detection: 0, containment: 0, recovery: 0, incident_response: 0,
    mission_inject: 0, penalty: -5, adjustment: 0, total: 300,
    last_updated_round: 42,
  },
  {
    rank: 2, team_id: "team-2", team: "Team 02", slug: "team-02",
    attack: 100, defense: 85, flag_defense: 0, availability: 90,
    detection: 0, containment: 0, recovery: 0, incident_response: 0,
    mission_inject: 0, penalty: 0, adjustment: 0, total: 275,
    last_updated_round: 42,
  },
];

const services = [
  {
    id: "instance-notes", service_id: "notes", service: "Vulnerable Notes",
    service_slug: "vulnerable-notes", team_id: "team-1", team_slug: "team-01",
    status: "healthy", image_digest: `sha256:${"a".repeat(64)}`,
    last_health_at: epoch - 3, updated_at: epoch - 3,
  },
  {
    id: "instance-vault", service_id: "vault", service: "File Vault",
    service_slug: "file-vault", team_id: "team-1", team_slug: "team-01",
    status: "degraded", image_digest: `sha256:${"b".repeat(64)}`,
    last_health_at: epoch - 18, updated_at: epoch - 2,
  },
];

const tournament = {
  id: "visual-cup", name: "LiveCTF Operations Cup",
  format: "single_elimination", status: "running",
  match_mode: "attack_defense", bracket_size: 4, current_stage: 2,
  winner_entry_id: null, disclosure: "public-bracket-no-credential-or-runtime-data",
  services: [{ id: "t-notes", slug: "vulnerable-notes", name: "Vulnerable Notes" }],
  entries: [1, 2, 3, 4].map((seed) => ({
    id: `entry-${seed}`, slug: `team-0${seed}`, name: `Team 0${seed}`,
    seed, status: seed > 2 ? "eliminated" : "registered",
  })),
  stages: [
    { id: "stage-1", sequence: 1, name: "Semifinal", status: "finalized", completed_at: epoch - 600 },
    { id: "stage-2", sequence: 2, name: "Final", status: "active", completed_at: null },
  ],
  fixtures: [
    {
      id: "fixture-1", stage_id: "stage-1", stage_sequence: 1,
      bracket_position: 1, status: "finalized", team_a_entry_id: "entry-1",
      team_b_entry_id: "entry-4", team_a: "Team 01", team_b: "Team 04",
      winner_entry_id: "entry-1", winner: "Team 01",
      result: { scores: { "entry-1": { total: 300 }, "entry-4": { total: 248 } } },
    },
    {
      id: "fixture-2", stage_id: "stage-1", stage_sequence: 1,
      bracket_position: 2, status: "finalized", team_a_entry_id: "entry-2",
      team_b_entry_id: "entry-3", team_a: "Team 02", team_b: "Team 03",
      winner_entry_id: "entry-2", winner: "Team 02",
      result: { scores: { "entry-2": { total: 275 }, "entry-3": { total: 261 } } },
    },
    {
      id: "fixture-final", stage_id: "stage-2", stage_sequence: 2,
      bracket_position: 1, status: "running", team_a_entry_id: "entry-1",
      team_b_entry_id: "entry-2", team_a: "Team 01", team_b: "Team 02",
      winner_entry_id: null, winner: null, result: {},
    },
  ],
};

async function installApi(page: Page, role: "competitor" | "operator" | "observer") {
  await page.clock.install({ time: new Date(epoch * 1000) });
  await page.addInitScript(({ roleName, accessToken }) => {
    localStorage.setItem("cr_match_mode", "attack_defense");
    localStorage.setItem("cr_match_id", "visual-match");
    if (roleName !== "observer") localStorage.setItem("cr_access_token", accessToken);
  }, { roleName: role, accessToken: token(role, role === "competitor" ? "team-1" : "") });

  await page.route("**:8100/**", async (route) => {
    const url = new URL(route.request().url());
    const path = url.pathname;
    const json = (body: unknown) => route.fulfill({
      status: 200, contentType: "application/json", body: JSON.stringify(body),
    });
    if (path.endsWith("/events/stream")) {
      return route.fulfill({
        status: 200, contentType: "text/event-stream",
        body: `id: fixture-1\ndata: ${JSON.stringify({
          event_id: "fixture-1", category: "system", type: "round_started",
          result: "active", timestamp: epoch,
        })}\n\n`,
      });
    }
    if (path.endsWith("/broadcast")) {
      expect(route.request().headers()["authorization"]).toBeUndefined();
      return json({
        schema_version: "broadcast-overlay.v1", generated_at: epoch,
        refresh_after_seconds: 5,
        match: {
          id: "visual-match", name: "Operation Fixture", mode: "attack_defense",
          status: "running", starts_at: epoch - 3600, round: 42,
          round_status: "active", round_ends_at: epoch + 78, server_time: epoch,
          tournament_id: "visual-cup",
        },
        scoreboard: {
          view: "public", delay_rounds: 3, last_public_round: 39,
          provisional: true, scoreboard: scores,
        },
        services: [
          {
            id: "public-notes", service_id: "notes", service: "vulnerable-notes",
            name: "Vulnerable Notes", status: "healthy", healthy: 2,
            degraded: 0, total: 2, updated_at: epoch,
          },
          {
            id: "public-vault", service_id: "vault", service: "file-vault",
            name: "File Vault", status: "degraded", healthy: 1,
            degraded: 1, total: 2, updated_at: epoch,
          },
        ],
        tournament,
        disclosure: {
          audience: "public-broadcast", scoreboard: "delayed-public-projection",
          scoreboard_delay_rounds: 3, last_public_round: 39,
          services: "aggregate-only", events_included: false,
          sensitive_fields_included: false,
        },
      });
    }
    if (path.endsWith("/state")) return json({
      id: "visual-match", name: "Operation Fixture", mode: "attack_defense",
      status: "running", starts_at: epoch - 3600, round: 42,
      round_status: "active", round_ends_at: epoch + 78, server_time: epoch,
      tournament_id: "visual-cup", tournament_fixture_id: "fixture-final",
      ...(role === "competitor" ? { team: { id: "team-1", name: "Team 01" } } : {}),
    });
    if (path.includes("/tournaments/visual-cup")) return json({
      ...tournament,
      ...(role === "competitor" ? {
        identity: {
          entry_id: "entry-1", credential_scope: "fresh-match-token-required-per-fixture",
          fixtures: [],
        },
      } : {}),
      ...(role === "operator" ? {
        disclosure: "operator-bracket-and-identity-map",
        fixtures: tournament.fixtures.map((fixture) => ({
          ...fixture, match_id: `match-${fixture.id}`,
        })),
      } : {}),
    });
    if (path.endsWith("/scoreboard")) return json({
      view: role === "operator" ? "operator" : "public", delay_rounds: 3,
      last_public_round: 39, provisional: true, scoreboard: scores,
    });
    if (path.endsWith("/services/me")) return json({ services });
    if (path.endsWith("/service-summary")) return json({ services: [
      {
        id: "public-notes", service_id: "notes", service: "vulnerable-notes",
        status: "healthy", healthy: 2, degraded: 0, total: 2, updated_at: epoch,
      },
      {
        id: "public-vault", service_id: "vault", service: "file-vault",
        status: "degraded", healthy: 1, degraded: 1, total: 2, updated_at: epoch,
      },
    ], disclosure: "aggregate-only" });
    if (path.includes("/operator/") && path.endsWith("/services")) {
      return json({ services: [
        ...services,
        ...services.map((item) => ({
          ...item, id: `${item.id}-2`, team_id: "team-2", team_slug: "team-02",
        })),
      ] });
    }
    if (path.endsWith("/attack-surface")) return json({
      teams: [{ id: "team-2", name: "Team 02", slug: "team-02" }],
      services: [
        { id: "notes", name: "Vulnerable Notes", slug: "vulnerable-notes" },
        { id: "vault", name: "File Vault", slug: "file-vault" },
      ],
      disclosure: "public-connectivity-only",
    });
    if (path.endsWith("/patches")) return json({ patches: [] });
    if (path.endsWith("/flags/submit")) return json({
      accepted: true, status: "accepted", score_delta: 10,
    });
    return json({});
  });
}

test("competitor navigation, keyboard submission, and visual baseline", async ({ page }) => {
  await page.setViewportSize({ width: 1920, height: 1080 });
  await installApi(page, "competitor");
  await page.goto("/?mode=attack_defense");
  await expect(page.getByRole("button", { name: "Attack Console" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Command Center" })).toHaveCount(0);
  await expect(page.locator(".operations-shell")).toHaveScreenshot(
    "competitor-battle-1920.png", { animations: "disabled" },
  );

  await page.getByRole("button", { name: "Attack Console" }).click();
  const input = page.getByLabel("Paste up to 20 flags, separated by whitespace");
  await input.fill(`FLAG{${"a".repeat(32)}}`);
  await input.press("Control+Enter");
  await expect(page.getByText("FLAG ACCEPTED")).toBeVisible();
  await expect(input).toBeFocused();
});

test("operator actions require a reason and keep focus trapped", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await installApi(page, "operator");
  await page.goto("/?mode=attack_defense");
  await expect(page.getByRole("button", { name: "Command Center" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Attack Console" })).toHaveCount(0);
  await page.getByRole("button", {
    name: "team-01 vulnerable-notes service details",
  }).click();
  await expect(page.getByText("SELECTED SERVICE")).toBeVisible();
  await page.getByRole("button", { name: "Restart service" }).click();
  let dialog = page.getByRole("dialog");
  await dialog.getByLabel("Audit reason").fill("restart verification");
  await expect(dialog.getByRole("button", { name: "Confirm action" })).toBeDisabled();
  await dialog.getByLabel(/Type vulnerable-notes/).fill("vulnerable-notes");
  await expect(dialog.getByRole("button", { name: "Confirm action" })).toBeEnabled();
  await dialog.getByRole("button", { name: "Cancel" }).click();
  await page.getByRole("button", { name: "Pause match" }).click();
  dialog = page.getByRole("dialog");
  await expect(dialog).toBeVisible();
  await expect(dialog.getByRole("button", { name: "Confirm action" })).toBeDisabled();
  await dialog.getByLabel("Audit reason").fill("visual authorization test");
  await expect(dialog.getByRole("button", { name: "Confirm action" })).toBeEnabled();
});

test("observer route is sanitized at laptop viewport", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await installApi(page, "observer");
  await page.goto("/observer/live?mode=attack_defense");
  await expect(page.getByText(/SANITIZED/)).toBeVisible();
  await expect(page.getByText("2/2")).toBeVisible();
  await expect(page.getByText("1/2")).toBeVisible();
  await expect(page.getByText(/sha256:/)).toHaveCount(0);
  await expect(page.getByText(/endpoint/i)).toHaveCount(1);
  await expect(page.getByRole("button", { name: "Patch Review" })).toHaveCount(0);
});

test("observer tournament bracket is broadcast-safe and visually stable", async ({ page }) => {
  await page.setViewportSize({ width: 1920, height: 1080 });
  await installApi(page, "observer");
  await page.goto("/observer/live?mode=attack_defense");
  await page.getByRole("button", { name: "Tournament Bracket" }).click();
  await expect(page.getByRole("heading", { name: "LiveCTF Operations Cup" })).toBeVisible();
  await expect(page.getByText("Semifinal")).toBeVisible();
  await expect(page.getByText("Final", { exact: true })).toBeVisible();
  await expect(page.getByText("match-fixture-final")).toHaveCount(0);
  await expect(page.getByText("BROADCAST SAFE", { exact: false })).toBeVisible();
  await expect(page.locator(".operations-shell")).toHaveScreenshot(
    "observer-tournament-1920.png", { animations: "disabled" },
  );
});

test("broadcast graphics stay public with an operator token present", async ({ page }) => {
  await page.setViewportSize({ width: 1920, height: 1080 });
  await installApi(page, "operator");
  await page.goto(
    "/broadcast/overlay?match_id=visual-match&layout=standings&background=solid",
  );
  await expect(page.getByRole("heading", { name: "Current standings" })).toBeVisible();
  await expect(page.getByText("DELAYED 3 ROUNDS")).toBeVisible();
  await expect(page.getByText("3 / 4")).toBeVisible();
  await expect(page.locator(".role-navigation")).toHaveCount(0);
  await expect(page.getByText(/sha256:/)).toHaveCount(0);
  await expect(page.getByText(/private-runtime/)).toHaveCount(0);
  await expect(page.locator(".broadcast-root")).toHaveScreenshot(
    "broadcast-standings-1920.png", { animations: "disabled" },
  );

  await page.goto(
    "/broadcast/overlay?match_id=visual-match&layout=bracket&background=solid",
  );
  await expect(page.getByRole("heading", { name: "LiveCTF Operations Cup" })).toBeVisible();
  await expect(page.getByText("match-fixture-final")).toHaveCount(0);
  await expect(page.locator(".broadcast-root")).toHaveScreenshot(
    "broadcast-bracket-1920.png", { animations: "disabled" },
  );

  await page.goto(
    "/broadcast/overlay?match_id=visual-match&layout=scorebar&background=transparent&max_teams=4",
  );
  await expect(page.getByRole("region", { name: "Public match scorebar" })).toBeVisible();
  await expect(page.locator("body")).toHaveCSS("background-color", "rgba(0, 0, 0, 0)");
  expect(await page.screenshot({ animations: "disabled", omitBackground: true }))
    .toMatchSnapshot("broadcast-scorebar-transparent-1920.png");
});
