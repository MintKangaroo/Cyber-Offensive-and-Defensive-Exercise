import { createHmac } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "@playwright/test";

const here = dirname(fileURLToPath(import.meta.url));
const dashboard = resolve(here, "..");
const repository = resolve(dashboard, "../..");
const output = resolve(repository, "docs/ui/screenshots");
const origin = process.env.LIVE_FIRE_UI_URL ?? "http://localhost:5178";
const matchId = process.env.ATTACK_DEFENSE_DEMO_MATCH_ID ?? "ad-demo";

function environment() {
  const result = {};
  for (const line of readFileSync(resolve(repository, ".env"), "utf8").split(/\r?\n/)) {
    if (!line || line.trimStart().startsWith("#") || !line.includes("=")) continue;
    const [key, ...rest] = line.split("=");
    result[key.trim()] = rest.join("=").trim().replace(/^['"]|['"]$/g, "");
  }
  return result;
}

function base64url(value) {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

function accessToken(role, teamId = "") {
  const secret = process.env.AUTH_JWT_SECRET ?? environment().AUTH_JWT_SECRET;
  if (!secret) throw new Error("AUTH_JWT_SECRET is required for role screenshots");
  const header = base64url({ alg: "HS256", typ: "JWT" });
  const payload = base64url({
    sub: `visual-${role}-${teamId || "operator"}`,
    role,
    team_id: teamId,
    match_id: matchId,
    type: "access",
    exp: Math.floor(Date.now() / 1000) + 600,
  });
  const signature = createHmac("sha256", secret)
    .update(`${header}.${payload}`).digest("base64url");
  return `${header}.${payload}.${signature}`;
}

async function capture(browser, name, viewport, role, activeRoute = "") {
  const context = await browser.newContext({
    viewport,
    colorScheme: "dark",
    reducedMotion: "reduce",
  });
  const page = await context.newPage();
  if (role !== "observer") {
    await page.addInitScript(({ token, match, mode }) => {
      localStorage.setItem("cr_access_token", token);
      localStorage.setItem("cr_match_id", match);
      localStorage.setItem("cr_match_mode", mode);
    }, {
      token: accessToken(role, role === "competitor" ? "team-1" : ""),
      match: matchId,
      mode: "attack_defense",
    });
  }
  await page.goto(
    `${origin}${activeRoute || "/"}?mode=attack_defense`,
    // The event stream is intentionally long-lived, so `networkidle` can
    // never be a valid readiness signal for this interface.
    { waitUntil: "domcontentloaded" },
  );
  await page.waitForTimeout(1500);
  await page.screenshot({
    path: resolve(output, name),
    fullPage: false,
  });
  await context.close();
}

const browser = await chromium.launch({ headless: true });
try {
  await capture(
    browser, "competitor-battle-1920x1080.png",
    { width: 1920, height: 1080 }, "competitor",
  );
  await capture(
    browser, "operator-command-1920x1080.png",
    { width: 1920, height: 1080 }, "operator",
  );
  await capture(
    browser, "observer-live-1920x1080.png",
    { width: 1920, height: 1080 }, "observer", "/observer/live",
  );
  await capture(
    browser, "observer-live-1440x900.png",
    { width: 1440, height: 900 }, "observer", "/observer/live",
  );
} finally {
  await browser.close();
}
