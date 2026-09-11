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
export function phaseEntries(raw: JsonObject): [string, JsonObject][] {
  return Object.entries(raw)
    .filter(
      ([key, value]) =>
        key.startsWith("phase_") &&
        value !== null &&
        typeof value === "object" &&
        !Array.isArray(value),
    )
    .map(([key, value]): [string, JsonObject] => [key, object(value)])
    .sort(([a], [b]) => phaseNumber(a) - phaseNumber(b));
}
const phaseNumber = (key: string) =>
  /^phase_\d+(?:_|$)/.test(key) ? Number(key.split("_")[1]) : 999;
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
    for (const [key, value] of phaseEntries(raw))
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
  if (!doc) throw new Error("Document no longer exists");
  if (!doc.document.hasIn(path))
    doc.document.setIn(path, doc.document.createNode([]));
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
/** Append only the requested node; existing IDs, dependencies and extension nodes stay intact. */
export function appendItem(
  source: string,
  index: number,
  path: KeyPath,
  value: unknown,
): string {
  const docs = parseSource(source);
  const doc = docs[index];
  if (!doc) throw new Error("Document no longer exists");
  if (!doc.document.hasIn(path))
    doc.document.setIn(path, doc.document.createNode([]));
  const seq = doc.document.getIn(path);
  if (!isSeq(seq))
    throw new Error(
      "The existing field is not a sequence. Correct it in YAML source first.",
    );
  seq.add(value);
  return docs.map((d) => d.document.toString()).join("");
}
export function appendPhase(
  source: string,
  index: number,
  key: string,
  actor: string,
  kind: "stages" | "objectives",
  dependency: string,
): string {
  const doc = parseSource(source)[index];
  if (!doc || doc.root !== "crossover_scenario")
    throw new Error("Phases require a crossover scenario.");
  const phases = phaseEntries(doc.raw);
  if (!/^phase_[1-9]\d*_[a-z][a-z0-9_]*$/.test(key))
    throw new Error("Phase ID must look like phase_2_investigation.");
  if (phases.some(([name]) => phaseNumber(name) === phaseNumber(key)))
    throw new Error(
      "This phase number already exists. Existing phases are never renumbered.",
    );
  if (
    phases.length &&
    phaseNumber(key) <= Math.max(...phases.map(([name]) => phaseNumber(name)))
  )
    throw new Error("Append a phase after the existing phase numbers.");
  if (
    phases.length &&
    !phases.some(([name]) => dependency === `${name}.completed`)
  )
    throw new Error(
      "Choose an existing phase completion to unlock this phase.",
    );
  if (!phases.length && dependency)
    throw new Error("The first phase starts immediately.");
  if (!["red", "blue"].includes(actor))
    throw new Error("Choose Red or Blue as the phase actor.");
  const value = {
    actor,
    ...(dependency ? { locked_until: dependency } : {}),
    ...(kind === "stages"
      ? {
          stages: [
            {
              stage: 1,
              name: "New training stage",
              objective_event:
                actor === "blue"
                  ? "blue_detection_success"
                  : "red_attack_started",
              match: {},
              points: 0,
              is_final: true,
            },
          ],
        }
      : {
          objectives: [
            {
              name: "New investigation objective",
              submit: "evidence_1",
              points: 0,
              answer: null,
            },
          ],
        }),
  };
  return editSource(source, index, [doc.root, key], value);
}
/** Built-in inject template ids (UI hint only; the runtime accepts inline specs too). */
export const INJECT_TEMPLATES = [
  "media-press-call",
  "exec-ciso-brief",
  "regulator-notice",
  "legal-hold",
] as const;
/** Create the embedded injects_campaign block once; never overwrite an existing one. */
export function appendCampaign(
  source: string,
  index: number,
  root: string,
): string {
  const docs = parseSource(source);
  const doc = docs[index];
  if (!doc) throw new Error("Document no longer exists");
  if (doc.document.hasIn([root, "injects_campaign"]))
    throw new Error("This scenario already has an inject campaign.");
  doc.document.setIn(
    [root, "injects_campaign"],
    {
      name: "crisis-comms",
      specs: [{ spec_id: "media", template_id: "media-press-call", at_sec: 0 }],
    },
  );
  return docs.map((d) => d.document.toString()).join("");
}
/** Append one inject spec with a unique spec_id; existing specs stay intact. */
export function appendCampaignSpec(
  source: string,
  index: number,
  root: string,
): string {
  const docs = parseSource(source);
  const doc = docs[index];
  if (!doc) throw new Error("Document no longer exists");
  const path: KeyPath = [root, "injects_campaign", "specs"];
  if (!doc.document.hasIn(path))
    doc.document.setIn(path, doc.document.createNode([]));
  const seq = doc.document.getIn(path);
  if (!isSeq(seq))
    throw new Error("The specs field is not a sequence. Correct it in YAML source first.");
  const existing = objects(seq.toJSON());
  const used = new Set(existing.map((s) => str(s.spec_id)));
  let n = existing.length + 1;
  while (used.has(`inject_${n}`)) n++;
  seq.add({
    spec_id: `inject_${n}`,
    channel: "internal",
    subject: "New inject",
    body: "",
    deadline_min: 30,
    rubric: [],
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
export const NEW_CROSSOVER = `# Instructor draft. Phase IDs and completion dependencies are explicit.\ncrossover_scenario:\n  id: CROSSOVER-DRAFT-01\n  name: New cross-domain exercise\n  target_asset: power_plant\n  time_limit_sec: 3600\n  phase_1_operations:\n    actor: red\n    emits_evidence: true\n    stages:\n      - stage: 1\n        name: Observe authorized range activity\n        objective_event: red_attack_started\n        match: {}\n        points: 0\n        is_final: true\n`;
export const NEW_SCENARIO = `# Instructor draft; publish explicitly after validation.\nscenario:\n  id: TRAINING-DRAFT-01\n  name: New authorized range exercise\n  target_asset: power_plant\n  description: Instructor-authored training scenario\n  difficulty: easy\n  time_limit_sec: 1800\n  stages:\n    - stage: 1\n      name: Observe the training objective\n      objective_event: red_attack_started\n      match: {}\n      points: 20\n      is_final: true\n  blue_objectives:\n    - name: Detect the observed activity\n      match_event: blue_detection_success\n      points: 20\n`;
