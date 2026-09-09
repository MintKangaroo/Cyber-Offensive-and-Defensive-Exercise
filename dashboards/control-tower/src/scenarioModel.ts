import { parseAllDocuments, isSeq, type Document } from "yaml";
import {
  object,
  objects,
  str,
  type JsonObject,
} from "@cyber-range/command-system";
export type KeyPath = (string | number)[];
export interface ScenarioDocument {
  index: number;
  root: string;
  raw: JsonObject;
  document: Document;
  stages: { path: KeyPath; raw: JsonObject; phase: string }[];
}
export function parseSource(source: string): ScenarioDocument[] {
  const docs = parseAllDocuments(source, { uniqueKeys: true });
  return docs.map((doc, index) => {
    if (doc.errors.length)
      throw new Error(doc.errors.map((e) => e.message).join("\n"));
    const value: unknown = doc.toJS({ maxAliasCount: 50 });
    const data = object(value);
    const root = data.scenario
      ? "scenario"
      : data.crossover_scenario
        ? "crossover_scenario"
        : "";
    if (!root)
      throw new Error(
        "Each document needs a scenario or crossover_scenario root.",
      );
    const raw = object(data[root]);
    const stages: ScenarioDocument["stages"] = [];
    objects(raw.stages).forEach((stage, i) =>
      stages.push({ path: [root, "stages", i], raw: stage, phase: "Stages" }),
    );
    for (const [key, value] of Object.entries(raw))
      if (key.startsWith("phase_"))
        objects(object(value).stages).forEach((stage, i) =>
          stages.push({
            path: [root, key, "stages", i],
            raw: stage,
            phase: key,
          }),
        );
    return { index, root, raw, document: doc, stages };
  });
}
/** Mode switching never serializes. Only an explicit visual edit writes YAML nodes. */
export function editSource(
  source: string,
  index: number,
  path: KeyPath,
  value: unknown,
): string {
  const docs = parseSource(source);
  const doc = docs[index];
  if (!doc) throw new Error("Document no longer exists");
  doc.document.setIn(path, value);
  return docs.map((d) => d.document.toString()).join("");
}
export function appendStage(
  source: string,
  index: number,
  path: KeyPath,
): string {
  const docs = parseSource(source);
  const doc = docs[index];
  const seq = doc.document.getIn(path);
  if (!isSeq(seq))
    throw new Error("Select an existing stage sequence in YAML first.");
  const stages = objects(seq.toJSON());
  const next =
    Math.max(
      0,
      ...stages.map((s) => (typeof s.stage === "number" ? s.stage : 0)),
    ) + 1;
  seq.add({
    stage: next,
    name: "New training stage",
    objective_event: "red_attack_started",
    match: {},
    points: 0,
  });
  return docs.map((d) => d.document.toString()).join("");
}
export function moveStage(
  source: string,
  index: number,
  path: KeyPath,
  from: number,
  to: number,
): string {
  const docs = parseSource(source);
  const seq = docs[index]?.document.getIn(path);
  if (
    !isSeq(seq) ||
    from < 0 ||
    to < 0 ||
    from >= seq.items.length ||
    to >= seq.items.length
  )
    throw new Error("Invalid stage move");
  const [node] = seq.items.splice(from, 1);
  seq.items.splice(to, 0, node);
  return docs.map((d) => d.document.toString()).join("");
}
export const scenarioId = (source: string) =>
  str(parseSource(source)[0]?.raw.id);
export const NEW_SCENARIO = `# Instructor draft; publish explicitly after validation.\nscenario:\n  id: TRAINING-DRAFT-01\n  name: New authorized range exercise\n  target_asset: power_plant\n  description: Instructor-authored training scenario\n  difficulty: easy\n  time_limit_sec: 1800\n  stages:\n    - stage: 1\n      name: Observe the training objective\n      objective_event: red_attack_started\n      match: {}\n      points: 20\n      is_final: true\n  blue_objectives:\n    - name: Detect the observed activity\n      match_event: blue_detection_success\n      points: 20\n`;
