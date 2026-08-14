import { describe, expect, it } from "vitest";
import {
  extractToken, findFlag, guidedCredentials, missionForTarget, noteSweepIds,
  parseEntries, systemFilePath, NOTES_MISSION, VAULT_MISSION,
} from "./guided";

describe("extractToken", () => {
  it("pulls access_token out of a login response", () => {
    expect(extractToken('{"access_token":"abc.def.ghi"}')).toBe("abc.def.ghi");
  });
  it("returns null on non-JSON or missing token", () => {
    expect(extractToken("not json")).toBeNull();
    expect(extractToken('{"other":1}')).toBeNull();
    expect(extractToken('{"access_token":""}')).toBeNull();
  });
});

describe("findFlag", () => {
  it("finds a FLAG token embedded in a note body", () => {
    const body = '{"id":3,"content":"secret is FLAG{abcdef0123456789abcdef0123456789}"}';
    expect(findFlag(body)).toBe("FLAG{abcdef0123456789abcdef0123456789}");
  });
  it("returns null when there is no flag", () => {
    expect(findFlag('{"content":"nothing here"}')).toBeNull();
    expect(findFlag("")).toBeNull();
  });
});

describe("parseEntries", () => {
  it("extracts a vault directory listing", () => {
    expect(parseEntries('{"path":"../../system","entries":["a.txt","b.txt"]}'))
      .toEqual(["a.txt", "b.txt"]);
  });
  it("is empty for a file (content) response or invalid body", () => {
    expect(parseEntries('{"path":"x","content":"hi"}')).toEqual([]);
    expect(parseEntries("boom")).toEqual([]);
  });
});

describe("path + sweep helpers", () => {
  it("builds a traversal read path", () => {
    expect(systemFilePath("deadbeef.txt")).toBe("../../system/deadbeef.txt");
  });
  it("sweeps sequential note ids from 1", () => {
    expect(noteSweepIds(3)).toEqual([1, 2, 3]);
    expect(noteSweepIds()[0]).toBe(1);
  });
  it("makes distinct credentials per seed", () => {
    expect(guidedCredentials(1).username).not.toBe(guidedCredentials(999999).username);
    expect(guidedCredentials(1).password.length).toBeGreaterThan(10);
  });
});

describe("missionForTarget", () => {
  it("maps the file-vault slug to the vault mission and everything else to notes", () => {
    expect(missionForTarget("file-vault")).toBe(VAULT_MISSION);
    expect(missionForTarget("vulnerable-notes")).toBe(NOTES_MISSION);
    expect(missionForTarget(undefined)).toBe(NOTES_MISSION);
  });
  it("every step defines a title, why and action", () => {
    for (const mission of [NOTES_MISSION, VAULT_MISSION]) {
      for (const step of mission.steps) {
        expect(step.title).toBeTruthy();
        expect(step.why).toBeTruthy();
        expect(step.action).toBeTruthy();
      }
    }
  });
});
