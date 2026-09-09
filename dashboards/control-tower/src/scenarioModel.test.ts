import { describe, it, expect } from "vitest";
import { resolve, join } from "node:path";
import { readdirSync, readFileSync } from "node:fs";
import {
  appendItem,
  appendPhase,
  appendStage,
  editSource,
  parseSource,
  phaseEntries,
  NEW_CROSSOVER,
} from "./scenarioModel";

describe("crossover visual authoring fidelity", () => {
  it("appends explicitly dependent phases without changing existing data or comments", () => {
    const original =
      NEW_CROSSOVER +
      "  extension: &preserved {rubric: human}\n  other: *preserved\n";
    const source = appendPhase(
      original,
      0,
      "phase_2_response",
      "blue",
      "objectives",
      "phase_1_operations.completed",
    );
    const result = parseSource(source)[0].raw;
    const { phase_2_response, ...unchanged } = result;
    expect(unchanged).toEqual(parseSource(original)[0].raw);
    expect(phase_2_response).toMatchObject({
      actor: "blue",
      locked_until: "phase_1_operations.completed",
      objectives: [{ answer: null, points: 0 }],
    });
    expect(source).toContain("# Instructor draft.");
    expect(source).toContain("&preserved");
    expect(source).toContain("*preserved");
  });
  it("rejects duplicate phase ordinals and missing dependencies instead of renumbering", () => {
    expect(() =>
      appendPhase(
        NEW_CROSSOVER,
        0,
        "phase_1_response",
        "blue",
        "stages",
        "phase_1_operations.completed",
      ),
    ).toThrow("already exists");
    expect(() =>
      appendPhase(NEW_CROSSOVER, 0, "phase_2_response", "blue", "stages", ""),
    ).toThrow("Choose an existing phase");
    expect(() =>
      appendPhase(
        NEW_CROSSOVER,
        0,
        "phase_2_response",
        "blue",
        "stages",
        "phase_9.completed",
      ),
    ).toThrow();
  });
  it("uses engine phase order and keeps stage IDs local when creating a new sequence", () => {
    const source = appendPhase(
      NEW_CROSSOVER,
      0,
      "phase_10_response",
      "blue",
      "objectives",
      "phase_1_operations.completed",
    );
    const stages = appendStage(source, 0, [
      "crossover_scenario",
      "phase_10_response",
      "stages",
    ]);
    expect(parseSource(stages)[0].stages.map((s) => s.raw.stage)).toEqual([
      1, 1,
    ]);
    expect(
      phaseEntries({ phase_10_x: {}, phase_2_x: {} }).map(([k]) => k),
    ).toEqual(["phase_2_x", "phase_10_x"]);
  });
  it("does not replace malformed existing objective fields or change other documents", () => {
    const source = NEW_CROSSOVER + "    objectives: {custom: true}\n";
    expect(() =>
      appendItem(
        source,
        0,
        ["crossover_scenario", "phase_1_operations", "objectives"],
        {},
      ),
    ).toThrow("not a sequence");
    const multi =
      NEW_CROSSOVER +
      "---\n" +
      NEW_CROSSOVER.replace("CROSSOVER-DRAFT-01", "CROSSOVER-DRAFT-02");
    const edited = editSource(
      multi,
      1,
      ["crossover_scenario", "phase_1_operations", "stages", 0, "points"],
      42,
    );
    expect(parseSource(edited)[0].raw).toEqual(parseSource(multi)[0].raw);
    expect(parseSource(edited)[1].stages[0].raw.points).toBe(42);
  });
  for (const kind of ["single", "crossover"]) {
    const directory = resolve(process.cwd(), "../../scenarios", kind);
    for (const file of readdirSync(directory).filter((name) =>
      name.endsWith(".yaml"),
    )) {
      it(`preserves the deployed ${kind}/${file} semantics after a name edit`, () => {
        const source = readFileSync(join(directory, file), "utf8");
        const before = parseSource(source);
        const edited = parseSource(
          editSource(source, 0, [before[0].root, "name"], "Reviewed exercise"),
        );
        expect(edited[0].raw).toEqual({
          ...before[0].raw,
          name: "Reviewed exercise",
        });
        expect(edited.slice(1).map((d) => d.raw)).toEqual(
          before.slice(1).map((d) => d.raw),
        );
      });
    }
  }
});
