import { describe, expect, it } from "vitest";
import { formatBroadcastCountdown, parseBroadcastOptions } from "./broadcastLogic";

describe("broadcast overlay public options", () => {
  it("accepts only bounded layouts, backgrounds, team counts, and colors", () => {
    expect(parseBroadcastOptions(new URLSearchParams(
      "match_id=final-1&layout=bracket&background=chroma&max_teams=99&accent=%23ff647c",
    ))).toEqual({
      matchId: "final-1", layout: "bracket", background: "chroma",
      maxTeams: 16, accent: "#ff647c",
    });
    expect(parseBroadcastOptions(new URLSearchParams(
      "layout=private&background=url(secret)&max_teams=-1&accent=red",
    ))).toEqual({
      matchId: "ad-demo", layout: "scorebar", background: "transparent",
      maxTeams: 2, accent: "#69afff",
    });
  });

  it("formats a server-anchored countdown without becoming negative", () => {
    expect(formatBroadcastCountdown(200, 100, 1_500)).toBe("01:39");
    expect(formatBroadcastCountdown(90, 100, 0)).toBe("00:00");
    expect(formatBroadcastCountdown(null, 100, 0)).toBe("--:--");
  });
});
