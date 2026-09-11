import { createContext, useContext, useEffect, useId, useState } from "react";
import {
  Button,
  object,
  objects,
  str,
  num,
  type JsonObject,
} from "@cyber-range/command-system";
import {
  INJECT_TEMPLATES,
  appendCampaign,
  appendCampaignSpec,
  appendItem,
  appendPhase,
  appendStage,
  phaseEntries,
  type KeyPath,
  type ScenarioDocument,
} from "../scenarioModel";

export type UpdateScenario = (path: KeyPath, value: unknown) => void;
export const ScenarioDraftContext = createContext<
  ((id: string, pending: boolean) => void) | null
>(null);

/** Structured criteria are applied explicitly; incomplete JSON never replaces valid YAML. */
export function CriteriaEditor({
  label,
  value,
  onApply,
}: {
  label: string;
  value: unknown;
  onApply: (value: JsonObject) => void;
}) {
  const serialized = JSON.stringify(value ?? {}, null, 2);
  const [draft, setDraft] = useState(serialized);
  const [error, setError] = useState("");
  const markPending = useContext(ScenarioDraftContext);
  const id = useId();
  const pending = draft !== serialized;
  useEffect(() => {
    markPending?.(id, pending);
    return () => markPending?.(id, false);
  }, [id, markPending, pending]);
  useEffect(() => {
    setDraft(serialized);
    setError("");
  }, [serialized]);
  return (
    <div className="field-wide criteria-editor">
      <label htmlFor={id}>{label}</label>
      <textarea
        id={id}
        rows={4}
        value={draft}
        spellCheck={false}
        onChange={(e) => setDraft(e.target.value)}
      />
      {error && (
        <p role="alert" className="text-critical">
          {error}
        </p>
      )}
      <Button
        disabled={draft === serialized}
        onClick={() => {
          try {
            const parsed: unknown = JSON.parse(draft);
            if (!parsed || typeof parsed !== "object" || Array.isArray(parsed))
              throw new Error("Criteria must be a JSON object.");
            onApply(parsed as JsonObject);
            setError("");
          } catch (e) {
            setError(e instanceof Error ? e.message : "Invalid criteria");
          }
        }}
      >
        Apply {label.toLowerCase()}
      </Button>
      {pending && (
        <>
          <Button
            onClick={() => {
              setDraft(serialized);
              setError("");
            }}
          >
            Revert criteria
          </Button>
          <small role="status">
            Unapplied criteria: apply this field before validating or saving.
          </small>
        </>
      )}
    </div>
  );
}

export function BlueObjectives({
  raw,
  root,
  update,
  append,
}: {
  raw: JsonObject;
  root: string;
  update: UpdateScenario;
  append: (path: KeyPath, value: unknown) => void;
}) {
  return (
    <div className="panel-padding">
      <h3>Blue response and recovery objectives</h3>
      <p className="muted">
        Use an observed event or alert and exact evidence criteria. Points
        follow the existing scoring engine.
      </p>
      {objects(raw.blue_objectives).map((o, i) => {
        const path: KeyPath = [root, "blue_objectives", i];
        return (
          <fieldset className="stage-fields" key={i}>
            <legend>Blue objective {i + 1}</legend>
            <TextField
              label="Objective"
              value={o.name}
              change={(v) => update([...path, "name"], v)}
            />
            <NumberField
              label="Points"
              value={o.points}
              change={(v) => update([...path, "points"], v)}
            />
            <TextField
              label="Match event"
              value={o.match_event}
              change={(v) => update([...path, "match_event"], v || null)}
            />
            <TextField
              label="Match alert"
              value={o.match_alert}
              change={(v) => update([...path, "match_alert"], v || null)}
            />
            <label>
              Time bonus
              <select
                value={o.time_bonus === true ? "true" : "false"}
                onChange={(e) =>
                  update([...path, "time_bonus"], e.target.value === "true")
                }
              >
                <option value="false">Disabled</option>
                <option value="true">Enabled</option>
              </select>
            </label>
            <CriteriaEditor
              label="Evidence criteria"
              value={o.match}
              onApply={(v) => update([...path, "match"], v)}
            />
          </fieldset>
        );
      })}
      <Button
        onClick={() =>
          append([root, "blue_objectives"], {
            name: "Verify asset recovery",
            points: 0,
            match_event: "asset_recovered",
            match: {},
            time_bonus: false,
          })
        }
      >
        Add Blue recovery objective
      </Button>
    </div>
  );
}

/**
 * Embedded crisis-communications inject campaign. Authored losslessly into the
 * scenario source under `injects_campaign:` and published through the existing
 * scenario file contract. The runtime (injects service) loads it by scenario id,
 * so the campaign is bound to this scenario without a free-form string. Rubric
 * grading stays manual — an instructor awards points per criterion at run time.
 */
export function CampaignEditor({
  raw,
  root,
  source,
  index,
  change,
  update,
  onError,
}: {
  raw: JsonObject;
  root: string;
  source: string;
  index: number;
  change: (value: string) => void;
  update: UpdateScenario;
  onError: (message: string) => void;
}) {
  const campaign = raw.injects_campaign;
  const mutate = (fn: () => string) => {
    try {
      change(fn());
    } catch (e) {
      onError(e instanceof Error ? e.message : "Visual edit failed");
    }
  };
  const base: KeyPath = [root, "injects_campaign"];
  if (campaign == null || typeof campaign !== "object" || Array.isArray(campaign))
    return (
      <div className="panel-padding">
        <h3>Crisis communications injects (optional)</h3>
        <p className="muted">
          Add a timed sequence of non-technical injects (media, exec, regulator,
          legal). It is published with the scenario and launched by scenario id;
          rubric grading is reviewed by an instructor at run time.
        </p>
        <Button onClick={() => mutate(() => appendCampaign(source, index, root))}>
          Add crisis-comms inject campaign
        </Button>
      </div>
    );
  const model = object(campaign);
  return (
    <div className="panel-padding">
      <h3>Crisis communications injects</h3>
      <p className="muted">
        Each spec is delivered to every team. Use a built-in template id or inline
        subject/body. A trigger fires a follow-up after an earlier spec is answered
        or its deadline is missed.
      </p>
      <TextField
        label="Campaign name"
        value={model.name}
        change={(v) => update([...base, "name"], v)}
      />
      {objects(model.specs).map((spec, i) => {
        const path: KeyPath = [...base, "specs", i];
        return (
          <fieldset className="stage-fields" key={i}>
            <legend>Inject {i + 1}</legend>
            <TextField
              label="Spec ID"
              value={spec.spec_id}
              change={(v) => update([...path, "spec_id"], v)}
            />
            <label>
              Template
              <input
                list="inject-template-ids"
                value={str(spec.template_id)}
                placeholder="built-in id or blank for inline"
                onChange={(e) =>
                  update([...path, "template_id"], e.target.value || null)
                }
              />
            </label>
            <TextField
              label="Channel"
              value={spec.channel}
              change={(v) => update([...path, "channel"], v || null)}
            />
            <TextField
              label="Subject (inline)"
              value={spec.subject}
              change={(v) => update([...path, "subject"], v || null)}
            />
            <TextField
              label="Body (inline)"
              value={spec.body}
              change={(v) => update([...path, "body"], v || null)}
            />
            <NumberField
              label="Deadline (minutes)"
              value={spec.deadline_min}
              change={(v) => update([...path, "deadline_min"], v)}
            />
            <NumberField
              label="Fire at (seconds)"
              value={spec.at_sec}
              change={(v) => update([...path, "at_sec"], v)}
            />
            <TextField
              label="Trigger after (spec ID, optional)"
              value={object(spec.trigger).after}
              change={(v) =>
                v
                  ? update([...path, "trigger"], {
                      after: v,
                      on: str(object(spec.trigger).on) || "answered",
                    })
                  : update([...path, "trigger"], null)
              }
            />
            {spec.trigger != null && (
              <label>
                Trigger on
                <select
                  value={str(object(spec.trigger).on) || "answered"}
                  onChange={(e) =>
                    update([...path, "trigger", "on"], e.target.value)
                  }
                >
                  <option value="answered">Previous inject answered</option>
                  <option value="deadline_missed">Previous deadline missed</option>
                </select>
              </label>
            )}
            <div className="field-wide">
              <strong className="muted">Rubric (manual grading)</strong>
              {objects(spec.rubric).map((crit, r) => (
                <div className="stage-fields" key={r}>
                  <TextField
                    label={`Criterion ${r + 1}`}
                    value={crit.criterion}
                    change={(v) => update([...path, "rubric", r, "criterion"], v)}
                  />
                  <NumberField
                    label="Max points"
                    value={crit.max}
                    change={(v) => update([...path, "rubric", r, "max"], v)}
                  />
                </div>
              ))}
              <Button
                onClick={() =>
                  mutate(() =>
                    appendItem(source, index, [...path, "rubric"], {
                      criterion: "New criterion",
                      max: 5,
                    }),
                  )
                }
              >
                Add rubric criterion
              </Button>
            </div>
          </fieldset>
        );
      })}
      <Button
        onClick={() => mutate(() => appendCampaignSpec(source, index, root))}
      >
        Add inject spec
      </Button>
      <datalist id="inject-template-ids">
        {INJECT_TEMPLATES.map((id) => (
          <option key={id} value={id} />
        ))}
      </datalist>
    </div>
  );
}

function TextField({
  label,
  value,
  change,
}: {
  label: string;
  value: unknown;
  change: (value: string) => void;
}) {
  return (
    <label>
      {label}
      <input value={str(value)} onChange={(e) => change(e.target.value)} />
    </label>
  );
}
function NumberField({
  label,
  value,
  change,
}: {
  label: string;
  value: unknown;
  change: (value: number) => void;
}) {
  return (
    <label>
      {label}
      <input
        type="number"
        value={num(value) ?? 0}
        onChange={(e) => change(Number(e.target.value))}
      />
    </label>
  );
}

export function PhaseEditor({
  document,
  source,
  change,
  update,
  onError,
}: {
  document: ScenarioDocument;
  source: string;
  change: (value: string) => void;
  update: UpdateScenario;
  onError: (message: string) => void;
}) {
  const phases = phaseEntries(document.raw);
  const nextNumber =
    Math.max(0, ...phases.map(([key]) => Number(key.split("_")[1]) || 0)) + 1;
  const [name, setName] = useState("");
  const [actor, setActor] = useState("blue");
  const [kind, setKind] = useState<"stages" | "objectives">("objectives");
  const [dependency, setDependency] = useState<string | null>(null);
  const proposedKey = name || `phase_${nextNumber}_investigation`;
  const proposedDependency =
    dependency ?? (phases.length ? `${phases.at(-1)?.[0]}.completed` : "");
  const { root, index } = document;
  const mutate = (fn: () => string) => {
    try {
      change(fn());
    } catch (e) {
      onError(e instanceof Error ? e.message : "Visual edit failed");
    }
  };
  return (
    <div className="panel-padding phase-editor">
      <h3>Exercise phases</h3>
      <p className="muted">
        The engine orders phases by their numeric ID. Completion dependencies
        are explicit. Stage cards below retain their original IDs.
      </p>
      {phases.map(([key, phase], order) => {
        const path = [root, key];
        const lock = str(phase.locked_until);
        const options = phases.slice(0, order).map(([id]) => `${id}.completed`);
        return (
          <details className="phase-card" key={key} open>
            <summary>
              <strong>{key}</strong>
              <span>
                {str(phase.actor).toUpperCase()} ·{" "}
                {order === 0
                  ? "Starts immediately"
                  : lock || "Missing unlock condition"}
              </span>
            </summary>
            <fieldset className="stage-fields">
              <legend>{key} settings</legend>
              <label>
                Phase actor
                <select
                  value={str(phase.actor)}
                  onChange={(e) => update([...path, "actor"], e.target.value)}
                >
                  {!["red", "blue"].includes(str(phase.actor)) && (
                    <option>{str(phase.actor)}</option>
                  )}
                  <option value="red">Red</option>
                  <option value="blue">Blue</option>
                </select>
              </label>
              <label>
                Unlock after
                <select
                  value={lock}
                  disabled={order === 0 && !lock}
                  onChange={(e) =>
                    update([...path, "locked_until"], e.target.value || null)
                  }
                >
                  <option value="">
                    {order === 0
                      ? "First phase starts immediately"
                      : "Missing — phase cannot unlock"}
                  </option>
                  {lock && !options.includes(lock) && (
                    <option value={lock}>{lock} (review dependency)</option>
                  )}
                  {options.map((id) => (
                    <option key={id}>{id}</option>
                  ))}
                </select>
              </label>
              <TextField
                label="Linked challenge reference"
                value={phase.linked_challenge}
                change={(v) => update([...path, "linked_challenge"], v || null)}
              />
              <label>
                Capture phase evidence
                <select
                  value={phase.emits_evidence === true ? "true" : "false"}
                  onChange={(e) =>
                    update(
                      [...path, "emits_evidence"],
                      e.target.value === "true",
                    )
                  }
                >
                  <option value="false">Disabled</option>
                  <option value="true">Enabled while phase is unlocked</option>
                </select>
              </label>
            </fieldset>
            <div className="panel-padding">
              <h4>Investigation objectives</h4>
              <p className="muted">
                The existing engine completes this phase after all objectives
                have been submitted; correct answers award objective points. An
                empty answer key requires instructor review and awards no
                automatic points.
              </p>
              {objects(phase.objectives).map((o, i) => (
                <fieldset className="stage-fields" key={i}>
                  <legend>
                    {key} objective {i + 1}
                  </legend>
                  <TextField
                    label="Objective name"
                    value={o.name}
                    change={(v) =>
                      update([...path, "objectives", i, "name"], v)
                    }
                  />
                  <TextField
                    label="Submission field"
                    value={o.submit}
                    change={(v) =>
                      update([...path, "objectives", i, "submit"], v)
                    }
                  />
                  <NumberField
                    label="Objective points"
                    value={o.points}
                    change={(v) =>
                      update([...path, "objectives", i, "points"], v)
                    }
                  />
                  <TextField
                    label="Instructor answer key"
                    value={o.answer}
                    change={(v) =>
                      update([...path, "objectives", i, "answer"], v || null)
                    }
                  />
                </fieldset>
              ))}
              <div className="toolbar">
                <Button
                  onClick={() =>
                    mutate(() => {
                      const existing = objects(phase.objectives);
                      let n = existing.length + 1;
                      while (
                        existing.some(
                          (o) =>
                            o.submit === `evidence_${n}` ||
                            o.name === `Investigation objective ${n}`,
                        )
                      )
                        n++;
                      return appendItem(
                        source,
                        index,
                        [...path, "objectives"],
                        {
                          name: `Investigation objective ${n}`,
                          submit: `evidence_${n}`,
                          points: 0,
                          answer: null,
                        },
                      );
                    })
                  }
                >
                  Add investigation objective to {key}
                </Button>
                <Button
                  onClick={() =>
                    mutate(() =>
                      appendStage(source, index, [...path, "stages"]),
                    )
                  }
                >
                  Add stage to {key}
                </Button>
              </div>
            </div>
            <details className="panel-padding">
              <summary>Instructor planning notes</summary>
              <p className="muted">
                These existing fields document intent. The current runner does
                not automatically execute success criteria, award parallel Blue
                points or unlock phases from completion_unlocks. Use event
                stages, investigation answers and locked_until for executable
                behavior.
              </p>
              <div className="stage-fields">
                <TextField
                  label="Phase objective description"
                  value={phase.objective}
                  change={(v) => update([...path, "objective"], v || null)}
                />
                <TextField
                  label="Evidence source reference"
                  value={phase.evidence_source}
                  change={(v) =>
                    update([...path, "evidence_source"], v || null)
                  }
                />
                <TextField
                  label="Parallel Blue goal (planning)"
                  value={object(phase.blue_parallel).goal}
                  change={(v) =>
                    phase.blue_parallel == null
                      ? update([...path, "blue_parallel"], {
                          goal: v,
                          points: 0,
                        })
                      : update([...path, "blue_parallel", "goal"], v)
                  }
                />
                {phase.blue_parallel != null && (
                  <NumberField
                    label="Parallel Blue points (planning)"
                    value={object(phase.blue_parallel).points}
                    change={(v) =>
                      update([...path, "blue_parallel", "points"], v)
                    }
                  />
                )}
              </div>
            </details>
          </details>
        );
      })}
      <fieldset className="stage-fields">
        <legend>Append a phase</legend>
        <TextField label="New phase ID" value={proposedKey} change={setName} />
        <label>
          New phase actor
          <select value={actor} onChange={(e) => setActor(e.target.value)}>
            <option value="blue">Blue</option>
            <option value="red">Red</option>
          </select>
        </label>
        <label>
          New phase workflow
          <select
            value={kind}
            onChange={(e) => setKind(e.target.value as "stages" | "objectives")}
          >
            <option value="objectives">
              Investigation with submitted evidence
            </option>
            <option value="stages">Event-driven stages</option>
          </select>
        </label>
        <label>
          New phase unlock condition
          <select
            value={proposedDependency}
            onChange={(e) => setDependency(e.target.value)}
          >
            {!phases.length && <option value="">Starts immediately</option>}
            {phases.map(([key]) => (
              <option key={key} value={`${key}.completed`}>
                {key}.completed
              </option>
            ))}
          </select>
        </label>
        <Button
          onClick={() =>
            mutate(() => {
              const next = appendPhase(
                source,
                index,
                proposedKey,
                actor,
                kind,
                proposedDependency,
              );
              setName("");
              setDependency(null);
              return next;
            })
          }
        >
          Add phase
        </Button>
      </fieldset>
    </div>
  );
}
